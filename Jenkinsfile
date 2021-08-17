pipeline {
    agent any
    environment {
        DOCKER_HUB_USERNAME = credentials('DOCKER_HUB_USERNAME')
        DOCKER_HUB_TOKEN = credentials('DOCKER_HUB_TOKEN')
        IMAGE_NAME="java-api"
        TAG="V-${BUILD_ID}"
    }
    stages {
        stage('DOCKER VERSION') {
        steps {
            sh '''
                docker --version
            '''
            }
        }
        stage('DOCKER BUILD') {
        steps {
            sh '''
                docker build -t $DOCKER_HUB_USERNAME/$IMAGE_NAME:$TAG  .
            '''
            }
        }
//         stage('DOCKER LOGIN') {
//         steps {
//             sh '''
//                 echo  $DOCKER_HUB_TOKEN | docker login --username $DOCKER_HUB_USERNAME --password-stdin
//             '''
//             }
//         }
//     stage('DOCKER PUSH') {
//         steps {
//             sh '''
//                 docker push $DOCKER_HUB_USERNAME/$IMAGE_NAME:$TAG
//             '''
//             }
//         }
//     stage('DOCKER LOGOUT') {
//         steps {
//             sh '''
//                 docker logout
//             '''
//             }
//         }
    }
}
