<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Backoffice</title>
</head>
<body>
    <h1>Admin Backoffice</h1>

    <c:if test="${not empty queueInfos}">
        <h2>Files d'attente</h2>
        <table border="1">
            <thead>
                <tr>
                    <th>Localisation</th>
                    <th>Service</th>
                    <th>Ticket en cours</th>
                    <th>Tous les Tickets</th>
                </tr>
            </thead>
            <tbody>
                <c:forEach var="queueInfo" items="${queueInfos}">
                    <tr>
                        <td>${queueInfo.locationName}</td>
                        <td>${queueInfo.serviceName}</td>
                        <td>
                            <c:if test="${not empty queueInfo.currentTicket}">
                                ${queueInfo.currentTicket.ticketNumber} - ${queueInfo.currentTicket.status}
                            </c:if>
                            <c:if test="${empty queueInfo.currentTicket}">
                                Pas de ticket en cours
                            </c:if>
                        </td>
                        <td>
                            <ul>
                                <c:forEach var="ticket" items="${queueInfo.allTickets}">
                                    <li>${ticket.ticketNumber} - ${ticket.status}</li>
                                </c:forEach>
                            </ul>
                        </td>
                    </tr>
                </c:forEach>
            </tbody>
        </table>
    </c:if>
    
    <!-- Navigation links -->
    <div class="nav">
        <ul>
            <li><a href="/admin/agents">Agents</a></li>
            <li><a href="/admin/clients">Clients</a></li>
            <li><a href="/logout">Se deconnecter</a></li>
        </ul>
    </div>
</body>
</html>
