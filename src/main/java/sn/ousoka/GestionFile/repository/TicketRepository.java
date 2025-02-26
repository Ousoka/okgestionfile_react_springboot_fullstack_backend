package sn.ousoka.GestionFile.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import sn.ousoka.GestionFile.model.Ticket;
import sn.ousoka.GestionFile.model.TicketStatus;
import java.util.Optional;
import java.util.List;

public interface TicketRepository extends JpaRepository<Ticket, Long> {

    List<Ticket> findByUserId(Long userId);

    List<Ticket> findByServiceId(Long serviceId);

    @Query("SELECT MAX(t.ticketNumber) FROM Ticket t WHERE t.service.id = :serviceId AND t.location.id = :locationId")
    Long findMaxTicketNumberByServiceAndLocation(@Param("serviceId") Long serviceId, @Param("locationId") Long locationId);

    @Query("SELECT MAX(t.positionInQueue) FROM Ticket t WHERE t.service.id = :serviceId AND t.location.id = :locationId")
    Long findMaxPositionByServiceAndLocation(@Param("serviceId") Long serviceId, @Param("locationId") Long locationId);

    @Query("SELECT COUNT(t) FROM Ticket t WHERE t.service.id = :serviceId AND t.location.id = :locationId AND t.positionInQueue < :position AND t.status = 'EN_ATTENTE'")
    Long countByServiceAndLocationAndPositionInQueueLessThan(
            @Param("serviceId") Long serviceId,
            @Param("locationId") Long locationId,
            @Param("position") Long position);


    List<Ticket> findByServiceIdAndLocationId(Long serviceId, Long locationId);

    Ticket findByServiceIdAndLocationIdAndStatus(Long serviceId, Long locationId, TicketStatus status);

    // trouver le ticket suivant dans la file
    Ticket findTopByServiceIdAndLocationIdAndStatusOrderByPositionInQueueAsc(Long serviceId, Long locationId, TicketStatus status);

    // trouver le dernier ticket termine
    Ticket findTopByServiceIdAndLocationIdAndStatusOrderByPositionInQueueDesc(Long serviceId, Long locationId, TicketStatus status);

    List<Ticket> findByServiceIdAndLocationIdOrderByPositionInQueueAsc(Long serviceId, Long locationId);

    Optional<Ticket> findFirstByServiceIdAndLocationIdAndStatus(Long serviceId, Long locationId, TicketStatus status);


    Optional<Ticket> findFirstByServiceIdAndLocationIdAndStatusOrderByPositionInQueueAsc(Long serviceId, Long locationId, TicketStatus status);

}
