import pyodbc
import re
cnxn = pyodbc.connect('Driver={SQL Server};Trusted_Connection=yes;Server=localhost;database=msdb',autocommit= True)
c = cnxn.cursor()
database_name = ['employee-db','employee_data','employee-email@', 'employee+name',"'(openbracketdb'","closebracketdb')'", 'employees#', '#specialcharcterdb@', 'mix-special#chardb@', "('db_with-special#char')"]
for value in database_name:
    c.execute('CREATE DATABASE "{}"'.format(value))
    c.execute('USE "{}"'.format(value))
    c.execute("create table dbo.Table_1(ID INT, Name nvarchar(50),email nvarchar(50), GenderId int)")
    for i in range(10000):
        c.execute("insert into dbo.Table_1 values(1,'jack','ana@123',12)")

