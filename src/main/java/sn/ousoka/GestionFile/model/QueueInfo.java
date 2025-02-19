package sn.ousoka.GestionFile.model;

import java.util.List;

public class QueueInfo {

    private String locationName;
    private String serviceName;
    private Ticket currentTicket;
    private List<Ticket> allTickets;

    // Constructeur 
    public QueueInfo(String locationName, String serviceName, Ticket currentTicket, List<Ticket> allTickets) {
        this.locationName = locationName;
        this.serviceName = serviceName;
        this.currentTicket = currentTicket;
        this.allTickets = allTickets;
    }

    // Getters and Setters
    public String getLocationName() {
        return locationName;
    }

    public void setLocationName(String locationName) {
        this.locationName = locationName;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public Ticket getCurrentTicket() {
        return currentTicket;
    }

    public void setCurrentTicket(Ticket currentTicket) {
        this.currentTicket = currentTicket;
    }

    public List<Ticket> getAllTickets() {
        return allTickets;
    }

    public void setAllTickets(List<Ticket> allTickets) {
        this.allTickets = allTickets;
    }
}
