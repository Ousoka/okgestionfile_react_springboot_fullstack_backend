package sn.ousoka.GestionFile.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import sn.ousoka.GestionFile.model.Ticket;
import sn.ousoka.GestionFile.model.TicketStatus;
import java.util.Optional;
import java.util.List;

public interface TicketRepository extends JpaRepository<Ticket, Integer> {

    List<Ticket> findByUserId(int userId);

    List<Ticket> findByServiceId(int serviceId);

    @Query("SELECT MAX(t.ticketNumber) FROM Ticket t WHERE t.service.id = :serviceId AND t.location.id = :locationId")
    Integer findMaxTicketNumberByServiceAndLocation(@Param("serviceId") int serviceId, @Param("locationId") int locationId);

    @Query("SELECT MAX(t.positionInQueue) FROM Ticket t WHERE t.service.id = :serviceId AND t.location.id = :locationId")
    Integer findMaxPositionByServiceAndLocation(@Param("serviceId") int serviceId, @Param("locationId") int locationId);

    @Query("SELECT COUNT(t) FROM Ticket t WHERE t.service.id = :serviceId AND t.location.id = :locationId AND t.positionInQueue < :position AND t.status = 'EN_ATTENTE'")
    int countByServiceAndLocationAndPositionInQueueLessThan(
            @Param("serviceId") int serviceId,
            @Param("locationId") int locationId,
            @Param("position") int position);


    List<Ticket> findByServiceIdAndLocationId(int serviceId, int locationId);

    Ticket findByServiceIdAndLocationIdAndStatus(int serviceId, int locationId, TicketStatus status);

    // trouver le ticket suivant dans la file
    Ticket findTopByServiceIdAndLocationIdAndStatusOrderByPositionInQueueAsc(int serviceId, int locationId, TicketStatus status);

    // trouver le dernier ticket termine
    Ticket findTopByServiceIdAndLocationIdAndStatusOrderByPositionInQueueDesc(int serviceId, int locationId, TicketStatus status);

    List<Ticket> findByServiceIdAndLocationIdOrderByPositionInQueueAsc(int serviceId, int locationId);

    Optional<Ticket> findFirstByServiceIdAndLocationIdAndStatus(int serviceId, int locationId, TicketStatus status);


    Optional<Ticket> findFirstByServiceIdAndLocationIdAndStatusOrderByPositionInQueueAsc(int serviceId, int locationId, TicketStatus status);

}
