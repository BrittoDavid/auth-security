insert into customers (email, pwd) values
                                       ('account@debuggeandoieas.com', '$2a$10$Ysn0.d6Ylii1Y0CE3YK5DuTkwywA1MlUcC1UwvCz25ZI5rgTM9UZO'),
                                       ('cards@debuggeandoieas.com', '$2a$10$Ysn0.d6Ylii1Y0CE3YK5DuTkwywA1MlUcC1UwvCz25ZI5rgTM9UZO'),
                                       ('loans@debuggeandoieas.com', '$2a$10$Ysn0.d6Ylii1Y0CE3YK5DuTkwywA1MlUcC1UwvCz25ZI5rgTM9UZO'),
                                        ('balance@debuggeandoieas.com', 'to_be_encoded');

insert into roles(role_name, description, id_customer) values
                                                           ('ROLE_ADMIN', 'cant view account endpoint', 1),
                                                           ('ROLE_ADMIN', 'cant view cards endpoint', 2),
                                                           ('ROLE_USER', 'cant view loans endpoint', 3),
                                                           ('ROLE_USER', 'cant view balance endpoint', 4);


--------------Data-------------
insert into partners(
    client_id,
    client_name,
    client_secret,
    scopes,
    grant_types,
    authentication_methods,
    redirect_uri,
    redirect_uri_logout
)
values ('debuggeandoideas',
            'debuggeando ideas',
            '$2a$10$v2jjQdxObou5FktwHIaTvOZGxThhIyDu28U8z5b8Jku1TemjUuwO2',
            'read,write',
            'authorization_code,refresh_token',
            'client_secret_basic,client_secret_jwt',
            'http://localhost:9000/authorized',
            'https://springone.io/authorized')