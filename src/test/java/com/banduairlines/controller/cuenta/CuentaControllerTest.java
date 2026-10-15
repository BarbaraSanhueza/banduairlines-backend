package com.banduairlines.controller.cuenta;

import com.banduairlines.dto.cuenta.RespuestaSolicitudCambioCorreo;
import com.banduairlines.dto.cuenta.RespuestaUsuario;
import com.banduairlines.exception.CodigosError;
import com.banduairlines.exception.GlobalExceptionHandler;
import com.banduairlines.exception.RecursoVencidoException;
import com.banduairlines.exception.ReglaNegocioException;
import com.banduairlines.model.enums.Nivel;
import com.banduairlines.model.enums.RolUsuario;
import com.banduairlines.service.cuenta.CambioContrasenaService;
import com.banduairlines.service.cuenta.CambioCorreoService;
import com.banduairlines.service.cuenta.RegistroPasajeroService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CuentaControllerTest {

    private MockMvc mockMvc;
    private RegistroPasajeroService registroService;
    private CambioCorreoService cambioCorreoService;
    private CambioContrasenaService cambioContrasenaService;

    @BeforeEach
    void configurar() {
        registroService = mock(RegistroPasajeroService.class);
        cambioCorreoService = mock(CambioCorreoService.class);
        cambioContrasenaService = mock(CambioContrasenaService.class);

        mockMvc = MockMvcBuilders.standaloneSetup(
                        new RegistroController(registroService),
                        new CambioCorreoController(cambioCorreoService),
                        new CambioContrasenaController(cambioContrasenaService)
                )
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void registroValido_retorna201YRespuestaEnEspanol() throws Exception {
        when(registroService.registrar(any())).thenReturn(new RespuestaUsuario(
                1L, "Valentina", "Rojas", "valentina@example.com",
                RolUsuario.PASAJERO, Nivel.BRONCE
        ));

        mockMvc.perform(post("/api/v1/auth/registro")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "nombres":"Valentina",
                                  "apellidos":"Rojas",
                                  "correo":"valentina@example.com",
                                  "contrasena":"Clave-2026",
                                  "confirmacionContrasena":"Clave-2026"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.idUsuario").value(1))
                .andExpect(jsonPath("$.rol").value("PASAJERO"))
                .andExpect(jsonPath("$.nivel").value("BRONCE"));
    }

    @Test
    void registroConDatosInvalidosORolEnviado_retorna400() throws Exception {
        mockMvc.perform(post("/api/v1/auth/registro")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "nombres":"Valentina",
                                  "apellidos":"Rojas",
                                  "correo":"correo-invalido",
                                  "contrasena":"corta",
                                  "confirmacionContrasena":"corta",
                                  "rol":"ADMINISTRADOR"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDACION"));
    }

    @Test
    void solicitarCambioCorreo_retorna202SinCodigo() throws Exception {
        when(cambioCorreoService.solicitar(any())).thenReturn(
                new RespuestaSolicitudCambioCorreo(
                        12L,
                        "c*****@example.com",
                        Instant.parse("2026-10-15T20:30:00Z")
                )
        );

        mockMvc.perform(post("/api/v1/cuentas/actual/cambio-correo/solicitudes")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"nuevoCorreo\":\"correo.nuevo@example.com\"}"))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.idSolicitud").value(12))
                .andExpect(jsonPath("$.correoEnmascarado").value("c*****@example.com"))
                .andExpect(jsonPath("$.codigo").doesNotExist());
    }

    @Test
    void confirmarConFormatoInvalido_retorna400() throws Exception {
        mockMvc.perform(put("/api/v1/cuentas/actual/cambio-correo/solicitudes/12")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"codigo\":\"123\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDACION"));
    }

    @Test
    void confirmarCodigoVencido_retorna410() throws Exception {
        when(cambioCorreoService.confirmar(eq(12L), any())).thenThrow(
                new RecursoVencidoException(
                        CodigosError.CODIGO_VENCIDO,
                        "El codigo de verificacion ha vencido"
                )
        );

        mockMvc.perform(put("/api/v1/cuentas/actual/cambio-correo/solicitudes/12")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"codigo\":\"482916\"}"))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value("CODIGO_VENCIDO"));
    }

    @Test
    void cancelarCambioCorreo_retorna204() throws Exception {
        mockMvc.perform(delete("/api/v1/cuentas/actual/cambio-correo/solicitudes/12"))
                .andExpect(status().isNoContent());

        verify(cambioCorreoService).cancelar(12L);
    }

    @Test
    void cambiarContrasena_retorna204() throws Exception {
        mockMvc.perform(put("/api/v1/cuentas/actual/contrasena")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "contrasenaActual":"Clave-2025",
                                  "nuevaContrasena":"Clave-2026",
                                  "confirmacionContrasena":"Clave-2026"
                                }
                                """))
                .andExpect(status().isNoContent());
    }

    @Test
    void contrasenaActualIncorrecta_retorna422() throws Exception {
        doThrow(new ReglaNegocioException("La contraseña actual es incorrecta")
                .conCodigo(CodigosError.CONTRASENA_ACTUAL_INCORRECTA))
                .when(cambioContrasenaService).cambiar(any());

        mockMvc.perform(put("/api/v1/cuentas/actual/contrasena")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "contrasenaActual":"Incorrecta-1",
                                  "nuevaContrasena":"Clave-2026",
                                  "confirmacionContrasena":"Clave-2026"
                                }
                                """))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.code").value("CONTRASENA_ACTUAL_INCORRECTA"));
    }
}
