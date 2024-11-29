package com.ecommerce.api_gateway.filter;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

import org.springframework.cloud.gateway.filter.GlobalFilter;

@Component
public class JwtAthFilter implements GlobalFilter {

    private final JwtUtil jwtUtil;

    @Autowired
    public JwtAthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }
    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap("Unauthorized".getBytes(StandardCharsets.UTF_8));
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
    private Mono<Void> expired(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap("Token Expired".getBytes(StandardCharsets.UTF_8));
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return unauthorized(exchange);
        }

        String token = authHeader.substring(7);

        try {
            // Validate the token
            if(jwtUtil.isTokenExpired(token)){
                return expired(exchange);
            }
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("X-User", jwtUtil.extractUsername(token))
                    .header("X-Roles", jwtUtil.getClaim(token,"roles").toString())
                    .header("X-UserID", jwtUtil.getClaim(token,"userId").toString())
                    .build();
            // Add claims to headers for downstream services
            mutatedRequest.getHeaders().forEach((key, value) -> {
                System.out.println(key + ": " + value);
            });

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        } catch (Exception e) {
            return unauthorized(exchange);
        }
    }
}
