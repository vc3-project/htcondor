#ifndef CONDOR_AWS_H
#define CONDOR_AWS_H

#include <map>

namespace AWS {
	class Query {
		public:
			Query() : includeResponseHeader( false ) { };
			virtual ~Query();

			virtual bool Send();

		protected:
			typedef std::map< std::string, std::string > AttributeValueMap;
			AttributeValueMap queryParameters;

			std::string serviceURL;
			std::string accessKeyFile;
			std::string secretKeyFile;

			std::string errorCode;
			std::string errorMessage;

			std::string resultString;

			bool includeResponseHeader;
	};

	class Stack {
		public:
			Stack( const std::string & projectID, const std::string & stackID, int desiredSize ) :
				ds( desiredSize ), pID( projectID ), sID( stackID ) { }
			const std::string & projectID() const { return pID; }
			int desiredSize() const { return ds; }

		protected:
			int			ds;
			std::string	pID;
			std::string sID;
	};

	typedef std::map< std::string, AWS::Stack > StackMap;

	class DescribeStacksQuery {
		public:
			DescribeStacksQuery();
			~DescribeStacksQuery();
	};
}

#endif /* CONDOR_AWS_H */
