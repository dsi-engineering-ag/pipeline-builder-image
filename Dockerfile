FROM maven:3.9.4-eclipse-temurin-21

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update

# Install docker-compose
RUN apt-get install -y python3-pip
RUN pip3 install --no-cache-dir docker-compose
RUN docker-compose -v

# Install cypress dependencies
RUN apt-get install -y libgtk2.0-0 libgtk-3-0 libgbm-dev libnotify-dev libgconf-2-4 libnss3 libxss1 libasound2 libxtst6 xauth xvfb


# Install gawk
RUN apt-get install -y gawk


# Downloading gcloud package
RUN curl https://dl.google.com/dl/cloudsdk/release/google-cloud-sdk.tar.gz > /tmp/google-cloud-sdk.tar.gz

# Installing the package
RUN mkdir -p /usr/local/gcloud \
  && tar -C /usr/local/gcloud -xvf /tmp/google-cloud-sdk.tar.gz \
  && /usr/local/gcloud/google-cloud-sdk/install.sh

# Adding the package path to local
ENV PATH $PATH:/usr/local/gcloud/google-cloud-sdk/bin

RUN gcloud components install kubectl

ENV USE_GKE_GCLOUD_AUTH_PLUGIN True
RUN gcloud components install gke-gcloud-auth-plugin

RUN curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"  | bash -s 4.5.7

RUN gcloud components update
