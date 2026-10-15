package com.banduairlines.repository;

import com.banduairlines.model.CredencialRenovacion;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.time.Instant;
import java.util.Optional;

@Repository
public interface CredencialRenovacionRepository
        extends JpaRepository<CredencialRenovacion, Long> {

    // Busca y bloquea una credencial durante su renovacion.
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredencialRenovacion> findByTokenHash(String tokenHash);

    // Busca y bloquea una sesion por su identificador.
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT c FROM CredencialRenovacion c WHERE c.id = :id")
    Optional<CredencialRenovacion> findByIdParaActualizar(@Param("id") Long id);

    // Busca las credenciales no revocadas de un usuario.
    @Lock(LockModeType.PESSIMISTIC_WRITE) List<CredencialRenovacion>
    findByUsuario_IdUsuarioAndFechaRevocacionIsNull(Long idUsuario);

    // Comprueba que una sesion exista, pertenezca al usuario, no este revocada ni haya expirado.
    boolean existsByIdAndUsuario_IdUsuarioAndFechaRevocacionIsNullAndFechaExpiracionAfter(
            Long idSesion, Long idUsuario, Instant ahora
    );
}
