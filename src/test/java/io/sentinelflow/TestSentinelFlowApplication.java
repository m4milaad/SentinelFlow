package io.sentinelflow;

import org.springframework.boot.SpringApplication;

public class TestSentinelFlowApplication {

    public static void main(String[] args) {
        SpringApplication.from(SentinelFlowApplication::main).with(TestcontainersConfiguration.class).run(args);
    }

}
