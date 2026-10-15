package com.banduairlines.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final RestAuthenticationEntryPoint authenticationEntryPoint;
    private final RestAccessDeniedHandler accessDeniedHandler;

    @Value("${app.security.enabled:false}")
    private boolean securityEnabled;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          RestAuthenticationEntryPoint authenticationEntryPoint,
                          RestAccessDeniedHandler accessDeniedHandler) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        if (!securityEnabled) {
            log.warn("SEGURIDAD DESACTIVADA (app.security.enabled=false): todas las rutas están abiertas. "
                    + "Solo para desarrollo, hasta que CUENTA entregue la validación JWT.");
        }

        http
                // 1. Mantener la configuracion CORS del proyecto.
                .cors(Customizer.withDefaults())

                // 2. API que utiliza Bearer tokens, sin autenticacion con cookies de sesion.
                .csrf(csrf -> csrf.disable())

                // 3. No crear sesiones HTTP para autenticacion.
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS))

                // 4. No utilizar login web ni HTTP Basic.
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())

                // 5. Respuestas JSON para errores 401 y 403.
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(
                                authenticationEntryPoint)
                        .accessDeniedHandler(
                                accessDeniedHandler))

                // 6. Reglas de autorizacion.
                .authorizeHttpRequests(auth -> {

                    // Permitir preflight de CORS.
                    auth.requestMatchers(
                            HttpMethod.OPTIONS,
                            "/**"
                    ).permitAll();

                    // Rutas publicas para cualquier metodo.
                    auth.requestMatchers(
                            SecurityRoutes.PUBLICAS
                    ).permitAll();

                    // Rutas publicas solamente para POST.
                    auth.requestMatchers(
                            HttpMethod.POST,
                            SecurityRoutes.PUBLICAS_POST
                    ).permitAll();

                    // Rutas publicas solamente para GET.
                    auth.requestMatchers(
                            HttpMethod.GET,
                            SecurityRoutes.PUBLICAS_GET
                    ).permitAll();

                    // Recuperacion de contrasena con codigo.
                    auth.requestMatchers(
                            HttpMethod.GET,
                            SecurityRoutes.RECUPERACION_CON_CODIGO
                    ).permitAll();

                    auth.requestMatchers(
                            HttpMethod.PUT,
                            SecurityRoutes.RECUPERACION_CON_CODIGO
                    ).permitAll();

                    if (securityEnabled) {

                        // 7. SUPERADMIN:
                        // Gestion de cuentas administrativas.
                        auth.requestMatchers(
                                SecurityRoutes.SOLO_SUPERADMIN
                        ).hasRole("SUPERADMIN");

                        // 8. ADMINISTRADOR:
                        // Otras funcionalidades administrativas.
                        auth.requestMatchers(
                                SecurityRoutes.SOLO_ADMIN
                        ).hasRole("ADMINISTRADOR");

                        // 9. PASAJERO:
                        // Funcionalidades de fidelizacion.
                        auth.requestMatchers(
                                SecurityRoutes.SOLO_PASAJERO
                        ).hasRole("PASAJERO");

                        // 10. PASAJERO y ADMINISTRADOR:
                        // Operaciones de perfil de cuenta.
                        auth.requestMatchers(
                                SecurityRoutes.PERFIL_CUENTA
                        ).hasAnyRole(
                                "PASAJERO",
                                "ADMINISTRADOR"
                        );

                        // 11. Cierre de sesion:
                        // Requiere un usuario autenticado.
                        auth.requestMatchers(
                                HttpMethod.POST,
                                SecurityRoutes.CIERRE_SESION
                        ).authenticated();

                        // 12. Otras rutas:
                        // Requieren autenticacion.
                        auth.anyRequest().authenticated();

                    } else {

                        // Desarrollo con seguridad desactivada.
                        auth.anyRequest().permitAll();
                    }
                })

                // 13. Incorporar nuestro filtro JWT a
                // la cadena de Spring Security.
                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter>
    jwtFilterRegistration(
            JwtAuthenticationFilter filter) {

        FilterRegistrationBean<JwtAuthenticationFilter>
                registration =
                new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);

        return registration;
    }

    /** Disponible para CUENTA (registro/login). No contiene lógica de negocio. */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
