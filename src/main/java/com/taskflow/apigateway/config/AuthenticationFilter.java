package com.taskflow.apigateway.config;

import com.taskflow.apigateway.config.JwtValidator;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtValidator jwtValidator;

    public AuthenticationFilter(JwtValidator jwtValidator) {
        this.jwtValidator = jwtValidator;
    }

    // Rotas públicas: não exigem token
    private static final List<String> PUBLIC_PATHS = List.of(
            "/api/auth/login",
            "/api/users"   // cadastro (POST) — público
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // Cadastro é POST em /api/users; login é /api/auth/login → liberar
        if (isPublic(path, request.getMethod().name())) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return unauthorized(exchange);
        }

        String token = authHeader.substring(7);
        if (!jwtValidator.isValid(token)) {
            return unauthorized(exchange);
        }

        // Token válido → segue para o roteamento
        return chain.filter(exchange);
    }

    private boolean isPublic(String path, String method) {
        if (path.equals("/api/auth/login")) return true;
        if (path.equals("/api/users") && method.equals("POST")) return true;
        return false;
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1;   // roda cedo, antes do roteamento
    }
}