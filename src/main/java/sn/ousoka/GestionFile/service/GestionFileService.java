package sn.ousoka.GestionFile.service;


import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sn.ousoka.GestionFile.model.OKService;
import sn.ousoka.GestionFile.model.Ticket;
import sn.ousoka.GestionFile.model.TicketStatus;
import sn.ousoka.GestionFile.model.Location;
import sn.ousoka.GestionFile.repository.ServiceRepository;
import sn.ousoka.GestionFile.repository.LocationRepository;
import sn.ousoka.GestionFile.repository.TicketRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.Optional;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import org.springframework.stereotype.Service;
import sn.ousoka.GestionFile.model.*;
import sn.ousoka.GestionFile.repository.*;

@Service
public class GestionFileService {
    @Autowired
    private ServiceRepository serviceRepository;

    @Autowired
    private LocationRepository locationRepository;

    @Autowired
    private TicketRepository ticketRepository;

    private static final Logger log = LoggerFactory.getLogger(GestionFileService.class);


    public List<OKService> getAllServices() {
    
        List<OKService> services = serviceRepository.findAll();
        if (services == null) {
            log.error("Pas de services found.");
        }
        return services;
    }


    public List<Location> getAllLocations() {
        return locationRepository.findAll();
    }


    public List<Ticket> getTicketsForService(int serviceId) {
        return ticketRepository.findByServiceId(serviceId);
    }

    public Optional<OKService> getServiceById(int serviceId) {
        return serviceRepository.findById(serviceId);
    }

    public Optional<Location> getLocationById(int locationId) {
        return locationRepository.findById(locationId);
    }


    public Ticket createTicket(OKService service, Location location, User user) {
        Ticket ticket = new Ticket();
        ticket.setService(service);
        ticket.setLocation(location);
        ticket.setUser(user);

        // genration du numero du ticket
        Integer maxTicketNumber = ticketRepository.findMaxTicketNumberByServiceAndLocation(service.getId(), location.getId());
        String newTicketNumber = String.format("%04d", (maxTicketNumber != null ? maxTicketNumber : 0) + 1);
        ticket.setTicketNumber(newTicketNumber);

        // assigner la pos dans la file
        Integer maxPosition = ticketRepository.findMaxPositionByServiceAndLocation(service.getId(), location.getId());
        int newPosition = (maxPosition != null ? maxPosition : 0) + 1;
        ticket.setPositionInQueue(newPosition);

        // statut par defaut
        ticket.setStatus(TicketStatus.EN_ATTENTE);


        // enregistrer le ticket
        ticketRepository.save(ticket);
        return ticket;
    }

    public int getPeopleAhead(int ticketId, int serviceId, int locationId) {
        // recup le ticket actuel
        Ticket currentTicket = ticketRepository.findById(ticketId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid ticket ID"));

        // Compter les tickets ayant une position < dans la même file 
        return ticketRepository.countByServiceAndLocationAndPositionInQueueLessThan(
                serviceId, locationId, currentTicket.getPositionInQueue());
    }



    public List<Ticket> getTicketsByServiceAndLocation(int serviceId, int locationId) {
        return ticketRepository.findByServiceIdAndLocationId(serviceId, locationId);
    }

    public Optional<Ticket> getTicketById(int ticketId) {
        return ticketRepository.findById(ticketId);
    }
    

    public Optional<Ticket> getCurrentTicket(int serviceId, int locationId) {
        Ticket ticket = ticketRepository.findByServiceIdAndLocationIdAndStatus(serviceId, locationId, TicketStatus.EN_COURS);
        return Optional.ofNullable(ticket);
    }


    public Optional<Ticket> startNextTicket(int serviceId, int locationId) {
    Optional<Ticket> currentTicket = getCurrentTicket(serviceId, locationId);

    //si un ticket est en cours 
    if (currentTicket.isPresent()) {
        return currentTicket; //le retourner
    }

    // trouver le prochain ticket en attente
    Optional<Ticket> nextTicket = ticketRepository.findFirstByServiceIdAndLocationIdAndStatusOrderByPositionInQueueAsc(
        serviceId, locationId, TicketStatus.EN_ATTENTE
    );

    // si un nextTicket exist -> le mettre en cours
    if (nextTicket.isPresent()) {
        Ticket ticket = nextTicket.get();
        ticket.setStatus(TicketStatus.EN_COURS);
        ticketRepository.save(ticket);
    }

        return nextTicket;
    }


    public void updateTicket(Ticket ticket) {
        ticketRepository.save(ticket);
    }


    public void updateTicketStatus(int ticketId, String action) {
        Ticket ticket = ticketRepository.findById(ticketId)
                .orElseThrow(() -> new IllegalArgumentException("ID du ticket invalid"));

        int serviceId = ticket.getService().getId();
        int locationId = ticket.getLocation().getId();

        if ("precedent".equals(action)) {
            if (ticket.getStatus() == TicketStatus.EN_COURS) {
                ticket.setStatus(TicketStatus.EN_ATTENTE);
                ticketRepository.save(ticket);

                // rendre le ticket precedent en cours si le status est termine
                Ticket lastTerminated = ticketRepository.findTopByServiceIdAndLocationIdAndStatusOrderByPositionInQueueDesc(
                        serviceId, locationId, TicketStatus.TERMINE);
                if (lastTerminated != null) {
                    lastTerminated.setStatus(TicketStatus.EN_COURS);
                    ticketRepository.save(lastTerminated);
                }
            } else if (ticket.getStatus() == TicketStatus.TERMINE) {
                // si ticket actuel est en cours, rendre le ticket termine le plus recent en tant que ticket actuel en cours 
                Ticket lastTerminated = ticketRepository.findTopByServiceIdAndLocationIdAndStatusOrderByPositionInQueueDesc(
                        serviceId, locationId, TicketStatus.TERMINE);
                if (lastTerminated != null) {
                    lastTerminated.setStatus(TicketStatus.EN_COURS);
                    ticketRepository.save(lastTerminated);
                }
            } else {
                throw new IllegalStateException("pas de ticket en cours pour faire un precedent.");
            }
        } else if ("suivant".equals(action)) {
            if (ticket.getStatus() == TicketStatus.EN_COURS) {
                ticket.setStatus(TicketStatus.TERMINE);
                ticketRepository.save(ticket);

                // mettre le nextTicket a en cours si ce dernier est en attente
                Ticket nextTicket = ticketRepository.findTopByServiceIdAndLocationIdAndStatusOrderByPositionInQueueAsc(
                        serviceId, locationId, TicketStatus.EN_ATTENTE);
                if (nextTicket != null) {
                    nextTicket.setStatus(TicketStatus.EN_COURS);
                    ticketRepository.save(nextTicket);
                }
            } else if (ticket.getStatus() == TicketStatus.EN_ATTENTE) {
                ticket.setStatus(TicketStatus.EN_COURS);
                ticketRepository.save(ticket);
            } else {
                throw new IllegalStateException("action invalid.");
            }
        }
    }

    // admin

    // recup de la file d'attente pour le couple {service, localisation}
    public QueueInfo getQueueInfo(OKService service, Location location) {
        // recup all tickets
        List<Ticket> allTickets = ticketRepository.findByServiceIdAndLocationIdOrderByPositionInQueueAsc(
                service.getId(), location.getId());

        // recup le ticket actuel (le ticket suivant dans la file avec le statut en attente)
        Ticket currentTicket = ticketRepository.findTopByServiceIdAndLocationIdAndStatusOrderByPositionInQueueAsc(
                service.getId(), location.getId(), TicketStatus.EN_COURS);

        String serviceLocation = location.getName();
        String serviceName = service.getName();

        return new QueueInfo(serviceLocation, serviceName, currentTicket, allTickets);
    }


}
