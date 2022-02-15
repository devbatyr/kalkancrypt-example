package kz.ups.iso20022authorization;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = {"kz.ups.iso20022authorization.controller", "kz.ups.iso20022authorization.service"})
public class Iso20022AuthorizationApplication {

    public static void main(String[] args) {
        SpringApplication.run(Iso20022AuthorizationApplication.class, args);
    }

}
