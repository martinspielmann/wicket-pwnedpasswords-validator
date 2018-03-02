pipeline {
    agent any
    tools {
        jdk 'jdk8'
        maven 'M3'
    }

    environment {
        JAVA_HOME = "${jdk}"
    }

    stages {
        stage('Prepare') {
            steps {
                checkout scm
            }
        }

        stage('Test') {
            steps {
                sh 'mvn install'
            }
        }

        stage('QA') {
            withSonarQubeEnv('sonar') {
                script {
                    def scannerHome = tool 'sonarqube-scanner'
                    sh "${scannerHome}/bin/sonar-scanner"
                }
            }
       }
    }
}
