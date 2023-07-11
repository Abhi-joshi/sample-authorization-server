FROM maven:3.9.3-eclipse-temurin-17-alpine AS build
COPY src /home/sample-authorization-server/src
COPY pom.xml /home/sample-authorization-server
RUN mvn -f /home/sample-authorization-server/pom.xml clean package -Dmaven.test.skip

FROM amazoncorretto:17
MAINTAINER abhishek
COPY --from=build /home/sample-authorization-server/target/sample-authorization-server-0.0.1-SNAPSHOT.jar sample-authorization-server-0.0.1-SNAPSHOT.jar
ENTRYPOINT ["java","-jar","/sample-authorization-server-0.0.1-SNAPSHOT.jar"]
