# SIPblocker-daemon
GO Asterisk AMI Event SipBlocker Daemon 

Возможно использовать как замену fail2ban. После сборки обработать напильником!

Can be used as a substitute for fail2ban

##Dependency:
```
Dependency Installed: 
    iptables
    postrgesql on any host

```

##Example create postgresql table:
```
CREATE TABLE fail2ban_temp
(
  id bigint NOT NULL DEFAULT nextval('sq_fail2ban_temp'::regclass),
  ip character varying(128),
  data timestamp without time zone NOT NULL DEFAULT now(),
  cause character varying(128),
  num character varying(4096)
)
```
