import pyodbc
cnxn = pyodbc.connect('Driver={SQL Server};Trusted_Connection=yes;Server=localhost;database=msdb')

c = cnxn.cursor()
q = 'select top 12 database_name, name, description, backup_start_date, backup_finish_date from dbo.backupset where type=\'L\' order by backup_start_date desc;'
c.execute(q)
for r in c:
    database_name, name, description, backup_start_date, backup_finish_date = r
    if 'DaLogBackup' not in name:
        exit(1)
    if 'Log truncated by Datrium Guest Agent.' != description:
        exit(1)
    print database_name, ',',  backup_start_date

