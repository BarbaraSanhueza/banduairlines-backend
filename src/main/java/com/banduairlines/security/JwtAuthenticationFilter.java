package com.banduairlines.security;

import com.banduairlines.model.Usuario;
import com.banduairlines.repository.CredencialRenovacionRepository;
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
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UsuarioRepository usuarioRepository;
    private final CredencialRenovacionRepository credencialRepository;

    public JwtAuthenticationFilter(
            JwtService jwtService,
            UsuarioRepository usuarioRepository,
            CredencialRenovacionRepository credencialRepository) {

        this.jwtService = jwtService;
        this.usuarioRepository = usuarioRepository;
        this.credencialRepository = credencialRepository;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain)
            throws ServletException, IOException {

        String autorizacion =
                request.getHeader("Authorization");

        // Peticiones sin Bearer: continuar sin autenticar.
        if (autorizacion == null
                || !autorizacion.startsWith("Bearer ")) {

            chain.doFilter(request, response);
            return;
        }

        String token = autorizacion.substring(7).trim();

        try {

            // 1. Validar el JWT y obtener usuario y sesion.
            JwtService.DatosAcceso datos =
                    jwtService.obtenerDatosAcceso(token);

            Long idUsuario = datos.idUsuario();
            Long idSesion = datos.idSesion();

            // 2. Comprobar que la sesion siga vigente.
            boolean sesionVigente =
                    credencialRepository
                            .existsByIdAndUsuario_IdUsuarioAndFechaRevocacionIsNullAndFechaExpiracionAfter(
                                    idSesion,
                                    idUsuario,
                                    Instant.now()
                            );

            if (!sesionVigente) {

                // La sesion fue revocada, expiro o no existe.
                SecurityContextHolder.clearContext();

                chain.doFilter(request, response);
                return;
            }

            // 3. Buscar al usuario actual en PostgreSQL.
            Optional<Usuario> usuarioOptional =
                    usuarioRepository.findById(idUsuario);

            if (usuarioOptional.isPresent()) {

                Usuario usuario = usuarioOptional.get();

                // 4. Verificar cuenta activa y rol.
                if (Boolean.TRUE.equals(usuario.getActivo())
                        && usuario.getRol() != null) {

                    // 5. Construir el principal autenticado.
                    UsuarioAutenticado principal =
                            new UsuarioAutenticado(
                                    usuario.getIdUsuario(),
                                    usuario.getCorreo(),
                                    usuario.getRol()
                            );

                    SimpleGrantedAuthority autoridad =
                            new SimpleGrantedAuthority(
                                    "ROLE_" + usuario.getRol().name()
                            );

                    UsernamePasswordAuthenticationToken autenticacion =
                            new UsernamePasswordAuthenticationToken(
                                    principal,
                                    null,
                                    List.of(autoridad)
                            );

                    // 6. Autenticar al usuario.
                    SecurityContextHolder.getContext()
                            .setAuthentication(autenticacion);
                }
            }

        } catch (JwtException | IllegalArgumentException ex) {

            // Token invalido, expirado o sin sesion.
            SecurityContextHolder.clearContext();
        }

        // 7. Continuar con Spring Security.
        chain.doFilter(request, response);
    }
}
