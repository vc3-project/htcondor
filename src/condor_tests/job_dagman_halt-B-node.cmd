executable	= ./job_dagman_halt-B-node.pl
arguments	= $(args)
universe	= scheduler
output		= job_dagman_halt-B-$(nodename).out
error		= job_dagman_halt-B-$(nodename).err
notification = NEVER
queue
