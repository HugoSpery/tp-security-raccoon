FROM jamesdbloom/docker-java7-maven:latest

WORKDIR /app

# Copier le code source
COPY ./raccoon-code/timing-measurements/ /app/

# Compiler le projet avec Maven (Java 7 avec JAXB natif)
RUN mvn clean package -DskipTests

# Copier les JAR compilés vers le répertoire de travail
RUN cp apps/RaccoonAttackPoC.jar . && cp -r apps/lib .

# Point d'entrée pour l'outil
ENTRYPOINT ["java", "-cp", "RaccoonAttackPoC.jar:lib/*", "de.rub.nds.raccoon.Main"]
CMD ["--help"]
