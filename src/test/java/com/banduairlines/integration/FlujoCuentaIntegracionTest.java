package com.banduairlines.integration;

import com.banduairlines.controller.cuenta.CambioCorreoController;
import com.banduairlines.controller.cuenta.RegistroController;
import com.banduairlines.exception.GlobalExceptionHandler;
import com.banduairlines.model.Usuario;
import com.banduairlines.repository.SolicitudCambioCorreoRepository;
import com.banduairlines.repository.UsuarioRepository;
import com.banduairlines.security.UsuarioActual;
import com.banduairlines.service.cuenta.ServicioCorreo;
import com.banduairlines.service.impl.CambioCorreoServiceImpl;
import com.banduairlines.service.impl.RegistroPasajeroServiceImpl;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class FlujoCuentaIntegracionTest {

    @Test
    void registroSolicitudYConfirmacionRecorrenElFlujoHttpCompleto() throws Exception {
        Map<Long, Usuario> usuarios = new LinkedHashMap<>();
        Map<Long, com.banduairlines.model.SolicitudCambioCorreo> solicitudes =
                new LinkedHashMap<>();
        AtomicLong idsUsuario = new AtomicLong(0);
        AtomicLong idsSolicitud = new AtomicLong(11);

        UsuarioRepository usuarioRepository = mock(UsuarioRepository.class);
        SolicitudCambioCorreoRepository solicitudRepository =
                mock(SolicitudCambioCorreoRepository.class);
        UsuarioActual usuarioActual = mock(UsuarioActual.class);
        ServicioCorreo servicioCorreo = mock(ServicioCorreo.class);

        when(usuarioRepository.existsByCorreo(any())).thenAnswer(invocacion -> {
            String correo = invocacion.getArgument(0);
            return usuarios.values().stream().anyMatch(u -> correo.equals(u.getCorreo()));
        });
        when(usuarioRepository.findByCorreo(any())).thenAnswer(invocacion -> {
            String correo = invocacion.getArgument(0);
            return usuarios.values().stream().filter(u -> correo.equals(u.getCorreo())).findFirst();
        });
        when(usuarioRepository.saveAndFlush(any(Usuario.class))).thenAnswer(invocacion -> {
            Usuario usuario = invocacion.getArgument(0);
            if (usuario.getIdUsuario() == null) {
                usuario.setIdUsuario(idsUsuario.incrementAndGet());
            }
            usuarios.put(usuario.getIdUsuario(), usuario);
            return usuario;
        });
        when(usuarioRepository.findById(any())).thenAnswer(invocacion ->
                Optional.ofNullable(usuarios.get(invocacion.<Long>getArgument(0))));

        when(solicitudRepository.saveAndFlush(any())).thenAnswer(invocacion -> {
            com.banduairlines.model.SolicitudCambioCorreo solicitud = invocacion.getArgument(0);
            solicitud.setIdSolicitud(idsSolicitud.incrementAndGet());
            solicitudes.put(solicitud.getIdSolicitud(), solicitud);
            return solicitud;
        });
        when(solicitudRepository.save(any())).thenAnswer(invocacion -> {
            com.banduairlines.model.SolicitudCambioCorreo solicitud = invocacion.getArgument(0);
            solicitudes.put(solicitud.getIdSolicitud(), solicitud);
            return solicitud;
        });
        when(solicitudRepository
                .findByUsuario_IdUsuarioAndFechaConfirmacionIsNullAndFechaCancelacionIsNull(any()))
                .thenAnswer(invocacion -> {
                    Long idUsuario = invocacion.getArgument(0);
                    return solicitudes.values().stream()
                            .filter(s -> s.getUsuario().getIdUsuario().equals(idUsuario))
                            .filter(s -> s.getFechaConfirmacion() == null)
                            .filter(s -> s.getFechaCancelacion() == null)
                            .toList();
                });
        when(solicitudRepository.findByIdSolicitudAndUsuario_IdUsuario(any(), any()))
                .thenAnswer(invocacion -> {
                    Long idSolicitud = invocacion.getArgument(0);
                    Long idUsuario = invocacion.getArgument(1);
                    return Optional.ofNullable(solicitudes.get(idSolicitud))
                            .filter(s -> s.getUsuario().getIdUsuario().equals(idUsuario));
                });

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
        RegistroPasajeroServiceImpl registroService =
                new RegistroPasajeroServiceImpl(usuarioRepository, encoder);
        CambioCorreoServiceImpl correoService = new CambioCorreoServiceImpl(
                usuarioRepository,
                solicitudRepository,
                usuarioActual,
                encoder,
                Optional.of(servicioCorreo),
                Clock.fixed(Instant.parse("2026-10-15T20:00:00Z"), ZoneOffset.UTC),
                30
        );

        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(
                        new RegistroController(registroService),
                        new CambioCorreoController(correoService)
                )
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();

        mockMvc.perform(post("/api/v1/auth/registro")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"nombres":"Valentina","apellidos":"Rojas","correo":"valentina@example.com","contrasena":"Clave-2026","confirmacionContrasena":"Clave-2026"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.idUsuario").value(1))
                .andExpect(jsonPath("$.nivel").value("BRONCE"));

        when(usuarioActual.exigirId()).thenReturn(1L);

        mockMvc.perform(post("/api/v1/cuentas/actual/cambio-correo/solicitudes")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"nuevoCorreo\":\"nuevo@example.com\"}"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.idSolicitud").value(12));

        ArgumentCaptor<String> codigoCaptor = ArgumentCaptor.forClass(String.class);
        verify(servicioCorreo).enviarCodigoCambioCorreo(
                org.mockito.ArgumentMatchers.eq("nuevo@example.com"),
                codigoCaptor.capture(),
                any()
        );

        mockMvc.perform(put("/api/v1/cuentas/actual/cambio-correo/solicitudes/12")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"codigo\":\"" + codigoCaptor.getValue() + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.correo").value("nuevo@example.com"))
                .andExpect(jsonPath("$.nivel").value("BRONCE"));
    }
}
