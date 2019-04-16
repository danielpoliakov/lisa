FROM node:10-alpine as builder

ARG webhost=localhost:4242

WORKDIR /frontend

COPY web_frontend ./

ENV REACT_APP_HOST=$webhost

RUN yarn && yarn build



FROM nginx:latest

RUN rm /etc/nginx/conf.d/default.conf

COPY docker/nginx/app.conf /etc/nginx/conf.d

COPY --from=builder /frontend/build /usr/share/nginx/html
