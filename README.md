Pem To JKS Converter
===
**NOTE** This utility assumes Java 11+.

This is a command-line Java utility that converts PEM-formatted private key,
certificate, and trust chain to a Java KeyStore. This keystore can then be used
by any Java-based application that accepts TLS connections (i.e. Tomcat, Jetty,
Apache-FTPServer, etc.)

To run
---
1. Clone this repository.
2. `./mvnw clean package`
3. `java -jar target/*-jar-with-dependencies.jar -help`
