
package com.banduairlines.security;

import com.banduairlines.model.Usuario;
import com.banduairlines.repository.UsuarioRepository;

import io.jsonwebtoken.JwtException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UsuarioRepository usuarioRepository;

    // Constructor: recibe el servicio JWT y el repositorio.
    public JwtAuthenticationFilter(
            JwtService jwtService,
            UsuarioRepository usuarioRepository) {

        this.jwtService = jwtService;
        this.usuarioRepository = usuarioRepository;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain)
            throws ServletException, IOException {

        // 1. Obtener la cabecera Authorization.
        String autorizacion =
                request.getHeader("Authorization");

        // 2. Si no hay Bearer token, continuar sin autenticar.
        if (autorizacion == null
                || !autorizacion.startsWith("Bearer ")) {

            chain.doFilter(request, response);
            return;
        }

        // 3. Extraer el JWT de la cabecera.
        String token = autorizacion.substring(7).trim();

        try {

            // 4. Validar JWT y obtener el ID del usuario.
            Long idUsuario =
                    jwtService.obtenerIdUsuario(token);

            // 5. Buscar al usuario en la base de datos.
            Optional<Usuario> usuarioOptional =
                    usuarioRepository.findById(idUsuario);

            if (usuarioOptional.isPresent()) {

                Usuario usuario = usuarioOptional.get();

                // 6. Comprobar que la cuenta este activa
                //    y tenga un rol asignado.
                if (Boolean.TRUE.equals(usuario.getActivo())
                        && usuario.getRol() != null) {

                    // 7. Crear el principal autenticado.
                    UsuarioAutenticado principal =
                            new UsuarioAutenticado(
                                    usuario.getId(),
                                    usuario.getEmail(),
                                    usuario.getRol()
                            );

                    // 8. Asignar la autoridad correspondiente.
                    SimpleGrantedAuthority autoridad =
                            new SimpleGrantedAuthority(
                                    "ROLE_" + usuario.getRol().name()
                            );

                    // 9. Crear el objeto Authentication.
                    UsernamePasswordAuthenticationToken autenticacion =
                            new UsernamePasswordAuthenticationToken(
                                    principal,
                                    null,
                                    List.of(autoridad)
                            );

                    // 10. Registrar al usuario en Spring Security.
                    SecurityContextHolder.getContext()
                            .setAuthentication(autenticacion);
                }
            }

        } catch (JwtException | IllegalArgumentException ex) {

            // JWT invalido o expirado.
            // La peticion continuara sin autenticacion.
            SecurityContextHolder.clearContext();
        }

        // 11. Continuar con el siguiente filtro.
        chain.doFilter(request, response);
    }
}

        /*
           ======================= INICIO ZONA MÓDULO CUENTA =======================
           TODO(CUENTA): implementar la validación del JWT aquí. Pasos esperados:
            1. Leer el header "Authorization: Bearer <token>". Si no existe, continuar sin autenticar.
            2. Validar firma y expiración con la clave app.jwt.secret.
            3. Si es válido, crear el Authentication y dejarlo en el contexto:
                 var principal = new UsuarioAutenticado(id, email, rol);
                 var auth = new UsernamePasswordAuthenticationToken(
                         principal, null,
                         List.of(new SimpleGrantedAuthority("ROLE_" + rol)));   // ver sección 7 del README
                 SecurityContextHolder.getContext().setAuthentication(auth);
            4. Si el token es inválido o expiró: NO lanzar excepción; SecurityContextHolder.clearContext()
               y continuar. La cadena responderá 401 por sí sola (RestAuthenticationEntryPoint).
           ======================== FIN ZONA MÓDULO CUENTA =========================
        */