<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agent Page</title>
</head>
<body>
    <div class="container mt-4">
        <h1>Agent Panel</h1>
        
        <!--  -->
        <c:if test="${not empty error}">
            <div class="alert alert-danger">${error}</div>
        </c:if>

        <!-- Service + Localisation -->
        <form method="get" action="/agent/tickets">
            <div class="row mb-3">
                <div class="col-md-6">
                    <label for="serviceId" class="form-label">Selectionner un Service:</label>
                    <select id="serviceId" name="serviceId" class="form-select" required>
                        <option value="" disabled selected>Selectionner un service</option>
                        <c:forEach var="service" items="${services}">
                            <option value="${service.id}" ${service.id == param.serviceId ? 'selected' : ''}>${service.name}</option>
                        </c:forEach>
                    </select>
                </div>
                <div class="col-md-6">
                    <label for="locationId" class="form-label">Selectionner une Localisation:</label>
                    <select id="locationId" name="locationId" class="form-select" required>
                        <option value="" disabled selected>Selectionner une Localisation</option>
                        <c:forEach var="location" items="${locations}">
                            <option value="${location.id}" ${location.id == param.locationId ? 'selected' : ''}>${location.name}</option>
                        </c:forEach>
                    </select>
                </div>
            </div>
            <button type="submit" class="btn btn-primary">Voir les Tickets</button>
        </form>

        <!-- ticket en cours -->
        <c:if test="${not empty currentTicket}">
            <h2 class="mt-4">Le ticket en cours de traitement</h2>
            <div class="alert alert-info">
                <strong>Numero du ticket:</strong> ${currentTicket.ticketNumber} <br>
                <strong>Position:</strong> ${currentTicket.positionInQueue} <br>
                <strong>Status:</strong> ${currentTicket.status}
            </div>
        </c:if>

        <!-- les tickets dans la file -->
        <c:if test="${not empty tickets}">
            <h2 class="mt-4">File d'attente du service</h2>
            <table class="table table-bordered">
                <thead>
                    <tr>
                        <th>Numero du ticket</th>
                        <th>Position</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <c:forEach var="ticket" items="${tickets}">
                        <tr>
                            <td>${ticket.ticketNumber}</td>
                            <td>${ticket.positionInQueue}</td>
                            <td>${ticket.status}</td>
                        </tr>
                    </c:forEach>
                </tbody>
            </table>

            <h3 class="mt-4">Actions</h3>            

            <form method="get" action="/agent/ticket/status">
                <input type="hidden" name="ticketId" value="${currentTicket != null ? currentTicket.id : 
                    (empty tickets ? null : (tickets[0].status == 'EN_ATTENTE' ? tickets[0].id : 
                    (tickets[tickets.size()-1].status == 'TERMINE' ? tickets[tickets.size()-1].id : null)))}" />
                <input type="hidden" name="serviceId" value="${param.serviceId}" />
                <input type="hidden" name="locationId" value="${param.locationId}" />

                    <!-- Preced -->
                    <button type="submit" name="action" value="precedent"
                    <c:if test="${not empty tickets}">
                        <c:set var="allEnAttente" value="true" />
                        <c:forEach var="ticket" items="${tickets}">
                            <c:if test="${ticket.status != 'EN_ATTENTE'}">
                                <c:set var="allEnAttente" value="false" />
                            </c:if>
                        </c:forEach>
                        <c:if test="${allEnAttente}">
                            disabled
                        </c:if>
                    </c:if>>Précédent</button>

                    <!-- Suivant -->
                    <button type="submit" name="action" value="suivant"
                    <c:if test="${not empty tickets}">
                        <c:set var="allTermine" value="true" />
                        <c:forEach var="ticket" items="${tickets}">
                            <c:if test="${ticket.status != 'TERMINE'}">
                                <c:set var="allTermine" value="false" />
                            </c:if>
                        </c:forEach>
                        <c:if test="${allTermine}">
                            disabled
                        </c:if>
                    </c:if>>Suivant</button>

            </form>
            
        </c:if>

        <!-- Navigation links -->
        <div class="nav">
            <ul>
                <li><a href="/logout">Se deconnecter</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
