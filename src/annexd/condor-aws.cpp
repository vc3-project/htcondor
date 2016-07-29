#include "condor_common.h"
#include "condor_debug.h"

#include <algorithm>
#include <openssl/hmac.h>
#include <curl/curl.h>
#include <expat.h>

#include "condor_base64.h"
#include "stat_wrapper.h"
#include "stl_string_utils.h"

#include "condor-aws.h"

//
// Utility function; inefficient.
//
bool readShortFile( const std::string & fileName, std::string & contents ) {
    int fd = safe_open_wrapper_follow( fileName.c_str(), O_RDONLY, 0600 );

    if( fd < 0 ) {
        dprintf( D_ALWAYS, "Failed to open file '%s' for reading: '%s' (%d).\n", fileName.c_str(), strerror( errno ), errno );
        return false;
    }

    StatWrapper sw( fd );
    unsigned long fileSize = sw.GetBuf()->st_size;

    char * rawBuffer = (char *)malloc( fileSize + 1 );
    assert( rawBuffer != NULL );
    unsigned long totalRead = full_read( fd, rawBuffer, fileSize );
    close( fd );
    if( totalRead != fileSize ) {
        dprintf( D_ALWAYS, "Failed to completely read file '%s'; needed %lu but got %lu.\n",
            fileName.c_str(), fileSize, totalRead );
        free( rawBuffer );
        return false;
    }
    contents.assign( rawBuffer, fileSize );
    free( rawBuffer );

    return true;
}

//
// "This function gets called by libcurl as soon as there is data received
//  that needs to be saved. The size of the data pointed to by ptr is size
//  multiplied with nmemb, it will not be zero terminated. Return the number
//  of bytes actually taken care of. If that amount differs from the amount
//  passed to your function, it'll signal an error to the library. This will
//  abort the transfer and return CURLE_WRITE_ERROR."
//
// We also make extensive use of this function in the XML parsing code,
// for pretty much exactly the same reason.
//
size_t appendToString( const void * ptr, size_t size, size_t nmemb, void * str ) {
    if( size == 0 || nmemb == 0 ) { return 0; }

    std::string source( (const char *)ptr, size * nmemb );
    std::string * ssptr = (std::string *)str;
    ssptr->append( source );

    return (size * nmemb);
}

//
// This function should not be called for anything in queryParameters,
// except for by AWS::Query::SendRequest().
//
std::string amazonURLEncode( const std::string & input ) {
    /*
     * See http://docs.amazonwebservices.com/AWSEC2/2010-11-15/DeveloperGuide/using-query-api.html
     *
     *
     * Since the GAHP protocol is defined to be ASCII, we're going to ignore
     * UTF-8, and hope it goes away.
     *
     */
    std::string output;
    for( unsigned i = 0; i < input.length(); ++i ) {
        // "Do not URL encode ... A-Z, a-z, 0-9, hyphen ( - ),
        // underscore ( _ ), period ( . ), and tilde ( ~ ).  Percent
        // encode all other characters with %XY, where X and Y are hex
        // characters 0-9 and uppercase A-F.  Percent encode extended
        // UTF-8 characters in the form %XY%ZA..."
        if( ('A' <= input[i] && input[i] <= 'Z')
         || ('a' <= input[i] && input[i] <= 'z')
         || ('0' <= input[i] && input[i] <= '9')
         || input[i] == '-'
         || input[i] == '_'
         || input[i] == '.'
         || input[i] == '~' ) {
            char uglyHack[] = "X";
            uglyHack[0] = input[i];
            output.append( uglyHack );
        } else {
            char percentEncode[4];
            int written = snprintf( percentEncode, 4, "%%%.2hhX", input[i] );
            ASSERT( written == 3 );
            output.append( percentEncode );
        }
    }

    return output;
}

#define SET_CURL_SECURITY_OPTION( A, B, C ) { \
    CURLcode rv##B = curl_easy_setopt( A, B, C ); \
    if( rv##B != CURLE_OK ) { \
        this->errorCode = "E_CURL_LIB"; \
        this->errorMessage = "curl_easy_setopt( " #B " ) failed."; \
        dprintf( D_ALWAYS, "curl_easy_setopt( %s ) failed (%d): '%s', failing.\n", \
            #B, rv##B, curl_easy_strerror( rv##B ) ); \
        return false; \
    } \
}

bool AWS::Query::Send() {
    //
    // Every request must have the following parameters:
    //
    //      Action, Version, AWSAccessKeyId, Timestamp (or Expires),
    //      Signature, SignatureMethod, and SignatureVersion.
    //

    if( queryParameters.find( "Action" ) == queryParameters.end() ) {
        this->errorCode = "E_INTERNAL";
        this->errorMessage = "No action specified in request.";
        dprintf( D_ALWAYS, "No action specified in request, failing.\n" );
        return false;
    }

	size_t j = serviceURL.find( "://" );
	if( j == std::string::npos || j + 3 >= serviceURL.length() ) {
		this->errorCode = "E_INVALID_SERVICE_URL";
		this->errorMessage = "Failed to parse service URL.";
		dprintf( D_ALWAYS, "Failed to parse service URL '%s': failed to find '://'.\n", serviceURL.c_str() );
		return false;
	}
    std::string hostAndPath = serviceURL.substr( j + 3 );

    j = hostAndPath.find( "/" );
    std::string httpRequestURI = "/";
    if( j != std::string::npos ) {
    	httpRequestURI = hostAndPath.substr( j );
    }
    std::string valueOfHostHeaderInLowercase = hostAndPath.substr( 0, j );
    std::transform( valueOfHostHeaderInLowercase.begin(),
                    valueOfHostHeaderInLowercase.end(),
                    valueOfHostHeaderInLowercase.begin(),
                    & tolower );

    //
    // The AWSAccessKeyId is just the contents of this->accessKeyFile,
    // and are (currently) 20 characters long.
    //
    std::string keyID;
    if( ! readShortFile( this->accessKeyFile, keyID ) ) {
        this->errorCode = "E_FILE_IO";
        this->errorMessage = "Unable to read from accesskey file '" + this->accessKeyFile + "'.";
        dprintf( D_ALWAYS, "Unable to read accesskey file '%s', failing.\n", this->accessKeyFile.c_str() );
        return false;
    }
    trim( keyID );
    queryParameters.insert( std::make_pair( "AWSAccessKeyId", keyID ) );

    //
    // This implementation computes signature version 2,
    // using the "HmacSHA256" method.
    //
    queryParameters.insert( std::make_pair( "SignatureVersion", "2" ) );
    queryParameters.insert( std::make_pair( "SignatureMethod", "HmacSHA256" ) );

    //
    // This implementation was written against the 2010-11-15 documentation.
    //
    // queryParameters.insert( std::make_pair( "Version", "2010-11-15" ) );

    // Upgrading (2012-10-01 is the oldest version that will work) allows us
    // to report the Spot Instance 'status-code's, which are much more
    // useful than the status codes.  *sigh*
    queryParameters.insert( std::make_pair( "Version", "2012-10-01" ) );

    //
    // We're calculating the signature now. [YYYY-MM-DDThh:mm:ssZ]
    //
    time_t now; time( & now );
    struct tm brokenDownTime; gmtime_r( & now, & brokenDownTime );
    char iso8601[] = "YYYY-MM-DDThh:mm:ssZ";
    strftime( iso8601, 20, "%Y-%m-%dT%H:%M:%SZ", & brokenDownTime );
    queryParameters.insert( std::make_pair( "Timestamp", iso8601 ) );

    /*
     * The tricky party of sending a Query API request is calculating
     * the signature.  See
     *
     * http://docs.amazonwebservices.com/AWSEC2/2010-11-15/DeveloperGuide/using-query-api.html
     *
     */

    // Step 1: Create the canonicalized query string.
    std::string canonicalizedQueryString;
    AttributeValueMap encodedParameters;
    AttributeValueMap::const_iterator i;
    for( i = queryParameters.begin(); i != queryParameters.end(); ++i ) {
        // Step 1A: The map sorts the query parameters for us.

        // Step 1B: Encode the parameter names and values.
        std::string name = amazonURLEncode( i->first );
        std::string value = amazonURLEncode( i->second );
        encodedParameters.insert( std::make_pair( name, value ) );

        // Step 1C: Separate parameter names from values with '='.
        canonicalizedQueryString += name + '=' + value;

        // Step 1D: Separate name-value pairs with '&';
        canonicalizedQueryString += '&';
    }
    // We'll always have a superflous trailing ampersand.
    canonicalizedQueryString.erase( canonicalizedQueryString.end() - 1 );

    // Step 2: Create the string to sign.
    std::string stringToSign = "POST\n"
                             + valueOfHostHeaderInLowercase + "\n"
                             + httpRequestURI + "\n"
                             + canonicalizedQueryString;

    // Step 3: "Calculate an RFC 2104-compliant HMAC with the string
    // you just created, your Secret Access Key as the key, and SHA256
    // or SHA1 as the hash algorithm."
    std::string saKey;
    if( ! readShortFile( this->secretKeyFile, saKey ) ) {
        this->errorCode = "E_FILE_IO";
        this->errorMessage = "Unable to read from secretkey file '" + this->secretKeyFile + "'.";
        dprintf( D_ALWAYS, "Unable to read secretkey file '%s', failing.\n", this->secretKeyFile.c_str() );
        return false;
    }
    trim( saKey );

    unsigned int mdLength = 0;
    unsigned char messageDigest[EVP_MAX_MD_SIZE];
    const unsigned char * hmac = HMAC( EVP_sha256(), saKey.c_str(), saKey.length(),
        (const unsigned char *)stringToSign.c_str(), stringToSign.length(), messageDigest, & mdLength );
    if( hmac == NULL ) {
        this->errorCode = "E_INTERNAL";
        this->errorMessage = "Unable to calculate query signature (SHA256 HMAC).";
        dprintf( D_ALWAYS, "Unable to calculate SHA256 HMAC to sign query, failing.\n" );
        return false;
    }

    // Step 4: "Convert the resulting value to base64."
    char * base64Encoded = condor_base64_encode( messageDigest, mdLength );
    std::string signatureInBase64 = base64Encoded;
    free( base64Encoded );

    // Generate the final URI.
    canonicalizedQueryString += "&Signature=" + amazonURLEncode( signatureInBase64 );
    std::string finalURI = this->serviceURL + "?" + canonicalizedQueryString;

    CURLcode rv = curl_global_init( CURL_GLOBAL_ALL );
    if( rv != 0 ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_global_init() failed.";
        dprintf( D_ALWAYS, "curl_global_init() failed, failing.\n" );
        return false;
    }

    CURL * curl = curl_easy_init();
    if( curl == NULL ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_init() failed.";
        dprintf( D_ALWAYS, "curl_easy_init() failed, failing.\n" );
        return false;
    }

    char errorBuffer[CURL_ERROR_SIZE];
    rv = curl_easy_setopt( curl, CURLOPT_ERRORBUFFER, errorBuffer );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_ERRORBUFFER ) failed.";
        dprintf( D_ALWAYS, "curl_easy_setopt( CURLOPT_ERRORBUFFER ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        curl_easy_cleanup( curl );
        return false;
    }

/*  // Useful for debuggery.  Could be rewritten with CURLOPT_DEBUGFUNCTION
    // and dumped via dprintf() to allow control via EC2_GAHP_DEBUG.
    rv = curl_easy_setopt( curl, CURLOPT_VERBOSE, 1 );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_VERBOSE ) failed.";
        dprintf( D_ALWAYS, "curl_easy_setopt( CURLOPT_VERBOSE ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        curl_easy_cleanup( curl );
        return false;
    }
*/

    dprintf( D_FULLDEBUG, "Request URI is '%s'\n", this->serviceURL.c_str() );
    rv = curl_easy_setopt( curl, CURLOPT_URL, this->serviceURL.c_str() );

    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_URL ) failed.";
        dprintf( D_ALWAYS, "curl_easy_setopt( CURLOPT_URL ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        curl_easy_cleanup( curl );
        return false;
    }

    rv = curl_easy_setopt( curl, CURLOPT_POST, 1 );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_POST ) failed.";
        dprintf( D_ALWAYS, "curl_easy_setopt( CURLOPT_POST ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        return false;
    }

    // We may, technically, need to replace '%20' in the canonicalized
    // query string with '+' to be compliant.
    size_t index = canonicalizedQueryString.find( "AWSAccessKeyId=" );
    if( index != std::string::npos ) {
        size_t skipLast = canonicalizedQueryString.find( "&", index + 14 );
        char swap = canonicalizedQueryString[ index + 15 ];
        canonicalizedQueryString[ index + 15 ] = '\0';
        char const * cqs = canonicalizedQueryString.c_str();
        if( skipLast == std::string::npos ) {
	        dprintf( D_FULLDEBUG, "Post body is '%s...'\n", cqs );
        } else {
        	dprintf( D_FULLDEBUG, "Post body is '%s...%s'\n", cqs, cqs + skipLast );
        }
        canonicalizedQueryString[ index + 15 ] = swap;
    } else {
        dprintf( D_FULLDEBUG, "Post body is '%s'\n", canonicalizedQueryString.c_str() );
    }

    rv = curl_easy_setopt( curl, CURLOPT_POSTFIELDS, canonicalizedQueryString.c_str() );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_POSTFIELDS ) failed.";
        dprintf( D_ALWAYS, "curl_easy_setopt( CURLOPT_POSTFIELDS ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        return false;
    }

    rv = curl_easy_setopt( curl, CURLOPT_NOPROGRESS, 1 );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_NOPROGRESS ) failed.";
        dprintf( D_ALWAYS, "curl_easy_setopt( CURLOPT_NOPROGRESS ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        curl_easy_cleanup( curl );
        return false;
    }

	if ( includeResponseHeader ) {
		rv = curl_easy_setopt( curl, CURLOPT_HEADER, 1 );
		if( rv != CURLE_OK ) {
			this->errorCode = "E_CURL_LIB";
			this->errorMessage = "curl_easy_setopt( CURLOPT_HEADER ) failed.";
			dprintf( D_ALWAYS, "curl_easy_setopt( CURLOPT_HEADER ) failed (%d): '%s', failing.\n",
					 rv, curl_easy_strerror( rv ) );
			return false;
		}
	}

    rv = curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, & appendToString );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_WRITEFUNCTION ) failed.";
        dprintf( D_ALWAYS, "curl_easy_setopt( CURLOPT_WRITEFUNCTION ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        curl_easy_cleanup( curl );
        return false;
    }

    rv = curl_easy_setopt( curl, CURLOPT_WRITEDATA, & this->resultString );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_setopt( CURLOPT_WRITEDATA ) failed.";
        dprintf( D_ALWAYS, "curl_easy_setopt( CURLOPT_WRITEDATA ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        curl_easy_cleanup( curl );
        return false;
    }

    //
    // Set security options.
    //
    SET_CURL_SECURITY_OPTION( curl, CURLOPT_SSL_VERIFYPEER, 1 );
    SET_CURL_SECURITY_OPTION( curl, CURLOPT_SSL_VERIFYHOST, 2 );

    // NB: Contrary to libcurl's manual, it doesn't strdup() strings passed
    // to it, so they MUST remain in scope until after we call
    // curl_easy_cleanup().  Otherwise, curl_perform() will fail with
    // a completely bogus error, number 60, claiming that there's a
    // 'problem with the SSL CA cert'.
    std::string CAFile = "";
    std::string CAPath = "";

    char * x509_ca_dir = getenv( "X509_CERT_DIR" );
    if( x509_ca_dir != NULL ) {
        CAPath = x509_ca_dir;
    }

    char * x509_ca_file = getenv( "X509_CERT_FILE" );
    if( x509_ca_file != NULL ) {
        CAFile = x509_ca_file;
    }

    if( CAPath.empty() ) {
        char * soap_ssl_ca_dir = getenv( "SOAP_SSL_CA_DIR" );
        if( soap_ssl_ca_dir != NULL ) {
            CAPath = soap_ssl_ca_dir;
        }
    }

    if( CAFile.empty() ) {
        char * soap_ssl_ca_file = getenv( "SOAP_SSL_CA_FILE" );
        if( soap_ssl_ca_file != NULL ) {
            CAFile = soap_ssl_ca_file;
        }
    }

    if( ! CAPath.empty() ) {
        dprintf( D_FULLDEBUG, "Setting CA path to '%s'\n", CAPath.c_str() );
        SET_CURL_SECURITY_OPTION( curl, CURLOPT_CAPATH, CAPath.c_str() );
    }

    if( ! CAFile.empty() ) {
        dprintf( D_FULLDEBUG, "Setting CA file to '%s'\n", CAFile.c_str() );
        SET_CURL_SECURITY_OPTION( curl, CURLOPT_CAINFO, CAFile.c_str() );
    }

    if( setenv( "OPENSSL_ALLOW_PROXY", "1", 0 ) != 0 ) {
        dprintf( D_FULLDEBUG, "Failed to set OPENSSL_ALLOW_PROXY.\n" );
    }

    rv = curl_easy_perform( curl );

    if( rv != 0 ) {
        this->errorCode = "E_CURL_IO";
        std::ostringstream error;
        error << "curl_easy_perform() failed (" << rv << "): '" << curl_easy_strerror( rv ) << "'.";
        this->errorMessage = error.str();
        dprintf( D_ALWAYS, "%s\n", this->errorMessage.c_str() );
        dprintf( D_FULLDEBUG, "%s\n", errorBuffer );
        curl_easy_cleanup( curl );
        return false;
    }

    unsigned long responseCode = 0;
    rv = curl_easy_getinfo( curl, CURLINFO_RESPONSE_CODE, & responseCode );
    if( rv != CURLE_OK ) {
        this->errorCode = "E_CURL_LIB";
        this->errorMessage = "curl_easy_getinfo() failed.";
        dprintf( D_ALWAYS, "curl_easy_getinfo( CURLINFO_RESPONSE_CODE ) failed (%d): '%s', failing.\n",
            rv, curl_easy_strerror( rv ) );
        curl_easy_cleanup( curl );
        return false;
    }

    curl_easy_cleanup( curl );

    if( responseCode != 200 ) {
        formatstr( this->errorCode, "E_HTTP_RESPONSE_NOT_200 (%lu)", responseCode );
        this->errorMessage = resultString;
        if( this->errorMessage.empty() ) {
            formatstr( this->errorMessage, "HTTP response was %lu, not 200, and no body was returned.", responseCode );
        }
        dprintf( D_ALWAYS, "Query did not return 200 (%lu), failing.\n",
            responseCode );
        dprintf( D_ALWAYS, "Failure response text was '%s'.\n", resultString.c_str() );
        return false;
    }

    dprintf( D_FULLDEBUG, "Response was '%s'\n", resultString.c_str() );
    return true;
}
