FROM openjdk:8-jre-alpine
LABEL maintainer="Cyril Dangerville <cyril.dangerville@projectdriver.eu>"
LABEL org.label-schema.schema-version = "1.0"
LABEL org.label-schema.vendor = "THALES"
LABEL org.label-schema.name="DRIVER+ EU Project - Testbed Authorization Service"
# LABEL org.label-schema.description=""

COPY src/test/resources /opt/driver-testbed-sec-authz-service
COPY docker/application.yml /application.yml

VOLUME /tmp
# Inside the container, copy the default policies to the folder that matches policyLocation's folder in conf/pdp.xml (missing directories in the path are created
RUN cp -r /opt/driver-testbed-sec-authz-service/conf/default-policies /opt/driver-testbed-sec-authz-service/data/policies
ARG JAR_FILE
COPY ${JAR_FILE} app.jar

EXPOSE 8080
EXPOSE 8443
ENV JAVA_OPTS="-Djava.security.egd=file:/dev/./urandom -Djava.awt.headless=true -Djavax.xml.accessExternalSchema=all -Xms1024m -Xmx2048m -XX:+UseConcMarkSweepGC -server"
ENTRYPOINT exec java $JAVA_OPTS -jar /app.jar