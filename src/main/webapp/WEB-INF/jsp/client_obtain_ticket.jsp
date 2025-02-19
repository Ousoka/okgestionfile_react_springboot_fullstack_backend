
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<!DOCTYPE html>
<html>

<head>
    <meta charset="UTF-8">
    <title>Client - Gestion File</title>
</head>

<body>
    <div class="client">
        <h1>Client - Gestion File</h1>

        <div class="client1">
            <h2 class="green">Sélectionnez un service</h2>

     <form action="/client_ticket" method="post">


                <div class="form-group">
                    <label for="service">Service :</label>
                    <select id="service" name="serviceId" required>
                        <option value="">Choisir un service</option>
                        <c:forEach var="service" items="${services}">
                            <option value="${service.id}">${service.name}</option>
                        </c:forEach>
                    </select>
                </div>

    
                <div class="form-group">
                    <label for="location">Localisation du Service :</label>
                    <select id="location" name="locationId" required>
                        <option value="">Choisir une localisation</option>
                        <c:forEach var="location" items="${locations}">
                            <option value="${location.id}">${location.name}</option>
                        </c:forEach>
                    </select>
                </div> 

                <div class="form-group">
                    <button type="submit" class="btn">Obtenir un ticket</button>
                </div>
            </form>

                <!-- Navigation links -->
                <div class="nav">
                    <ul>
                        <li><a href="/client_view_tickets">Voir mes tickets</a></li>
                        <li><a href="/client_home">Acceuil client</a></li>
                        <li><a href="/logout">Se deconnecter</a></li>
                    </ul>
                </div>

        </div>
    </div>
</body>

</html>
