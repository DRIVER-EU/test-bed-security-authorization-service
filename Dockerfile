FROM openjdk:8-jdk-alpine
LABEL maintainer="Cyril Dangerville <http://scr.im/cdan>"
LABEL org.label-schema.schema-version = "1.0"
LABEL org.label-schema.vendor = "Thales Services"
VOLUME /tmp
ARG JAR_FILE
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-Djava.awt.headless=true","-Djavax.xml.accessExternalSchema=all","-Xms1024m","-Xmx2048m","-XX:+UseConcMarkSweepGC","-server","-jar","/app.jar"]
