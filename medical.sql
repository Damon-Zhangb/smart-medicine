CREATE DATABASE medical;
USE  medical;


-- -----------------------
-- table for aoto
-- -----------------------
CREATE TABLE aoto (
aoto_id int NOT NULL AUTO_INCREMENT,
aoto_name varchar(255),
PRIMARY KEY(aoto_id)
)ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------
-- table for information
-- ------------------
CREATE TABLE information(
user_id int NOT NULL AUTO_INCREMENT,
user_name varchar(30) NOT NULL,
user_password varchar(100) NOT NULL,
user_sex int NOT NULL,
age int DEFAULT NULL,
id_number VARCHAR(20) DEFAULT NULL,
nation varchar(20) DEFAULT NULL,
marriage varchar(10),
native_place varchar(50) DEFAULT NULL,
phone_number varchar(11) DEFAULT NULL,
address varchar(50),
grave varchar(50),
public_key varchar(256),
private_key varchar(256),
PRIMARY KEY(user_id)
)ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------
-- table for doctor
-- ---------------------
CREATE TABLE doctor(
doctor_id int NOT NULL AUTO_INCREMENT,
aoto_id int DEFAULT NULL,
gender int NOT NULL,
doctor_name varchar(20) DEFAULT NULL,
doctor_number varchar(11) DEFAULT NULL,
doctor_password varchar(100) NOT NULL,
do_public_key varchar(256),
do_private_key varchar(256),
PRIMARY KEY(doctor_id),
foreign key(aoto_id) references aoto(aoto_id)
)ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- -------------------
-- table for make
-- -------------------
CREATE TABLE make(
make_id int NOT NULL AUTO_INCREMENT,
doctor_id int DEFAULT NULL,
make_time varchar(50) DEFAULT NULL,
PRIMARY KEY(make_id),
foreign key(doctor_id) references doctor(doctor_id)
)ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -------------------
-- table for cases
-- -------------------
CREATE TABLE view_cases(
cases_id int NOT NULL AUTO_INCREMENT,
time varchar(50) DEFAULT NULL,
hospital varchar(50) DEFAULT NULL,
aoto_id int DEFAULT NULL,
department varchar(50),
odd_numbers varchar(50),
information_id int DEFAULT NULL,
illness_history VARCHAR(200) DEFAULT NULL,
family varchar(50),
build varchar(50),
assist varchar(50),
medicine varchar(50),
tcms varchar(50),
main_suit varchar(50),
doctor_id int DEFAULT NULL,
PRIMARY KEY(cases_id),
foreign key(information_id) references information(user_id),
foreign key(aoto_id) references aoto(aoto_id),
foreign key(doctor_id) references doctor(doctor_id)
)ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------
-- tbale for reservation
-- --------------------
CREATE TABLE reservation(
reservation_id int NOT NULL AUTO_INCREMENT,
patient_id int DEFAULT NULL,
doctor_id int DEFAULT NULL,
aoto_id int DEFAULT NULL,
reservation_time varchar(50) DEFAULT NULL,
cost int,
reservation_status int,
authorization_code varchar(50),
code_state int,
reservation_number int,
PRIMARY KEY(reservation_id),
foreign key(patient_id) references information(user_id),
foreign key(doctor_id) references doctor(doctor_id),
foreign key(aoto_id) references aoto(aoto_id)
)ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------
-- table for organization
-- ----------------------
CREATE TABLE organization(
organization_id int NOT NULL AUTO_INCREMENT,
organization_name varchar(20) NOT NULL,
PRIMARY KEY(organization_id)
)ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------
-- tbale for components
-- ----------------------
CREATE TABLE components(
components_id int NOT NULL AUTO_INCREMENT,
organization_id int DEFAULT NULL,
components_name varchar(20) NOT NULL,
network_id varchar(20) DEFAULT NULL,
type varchar(20),
domain_name varchar(20),
port varchar(20),
ip varchar(20),
health_check_port varchar(20),
PRIMARY KEY(components_id)
)ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- ------------------
-- table for network 
-- ------------------
CREATE TABLE network(
network_id int AUTO_INCREMENT,
network_name varchar(20),
introduction varchar(50),
version varchar(20),
consensus_type int,
create_date varchar(50),
PRIMARY KEY(network_id)
)ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------
-- table for generation
-- ----------------------
CREATE TABLE generation(
cip_id int NOT NULL AUTO_INCREMENT,
to_id int NOT NULL,
cipher_text varchar(5000),
PRIMARY KEY(cip_id)
)ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;