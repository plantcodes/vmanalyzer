### vmstd ###

A damon process monitors VMs network characters,
and reports statistical information periodly.

To make it works well, the following files should be exist:

* /var/vmstd/mac.list
* /var/run/write.1
* /var/run/vmstd.pid
* /var/vmstd/report.json

The `/var/vmstd/mac.list` is the records like `00:16:33:4d:5e:5f vmname`.

The `/var/run/write.1` 's content is 1 or 0, the flag that 
the daemon is write report to file `/var/vmstd.report.json`.

The `/var/run/vmstd.pid` is the lockfile to make sure that only one copy
of the daemon process in running in the system.

And the statistic information is periodically reported in file `/var/vmstd/report.json`.
