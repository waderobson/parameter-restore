# parameter-restore
This handy tool is will make backing up your parameters in parameter store quick and easy. 


```
➜  parameter-restore git:(master) ✗ ./parameter-restore 

usage: parameter-restore [flags] [action]

Examples:
Backup: 
	parameter-restore -json-file=output.json backup
	parameter-restore -json-file=output.json -namespace=/Team backup
Restore:
	parameter-restore -json-file=input.json restore
  -concurrency int
    	May increase restore speed in some cases (default 1)
  -json-file string
    	Path to json file
  -namespace string
    	Filter for namespace. Same as 'someparameter*'
  -profile string
    	Use a specific profile from your credential file
```