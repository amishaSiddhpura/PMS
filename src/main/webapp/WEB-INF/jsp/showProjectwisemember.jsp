<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@page session="true"%>
<html>
<head>
    <title>Show Projects</title>
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
</head>
<body>
<jsp:include page="menu.jsp" />
<center>
    <h1 style="color: red;">Show Projects</h1>

    <table class="w3-table-all w3-card-4">
        <tr>
            <th style="text-align: center">PROJECT ID</th>
            <th style="text-align: center">TITLE</th>
            <th style="text-align: center">DESCRIPTION</th>
            <th style="text-align: center">SHOW MEMBERS</th>
        </tr>
        <c:forEach var="listValue" items="${projects}">
            <tr>
                <td style="text-align: center">${listValue.id}</td>
                <td style="text-align: center">${listValue.title}</td>
                <td style="text-align: center">${listValue.description}</td>
                <td style="text-align: center"><a href="/showMembers?projectId=${listValue.id}">Show Members</a> </td>
            </tr>
        </c:forEach>
    </table>

</center>
</body>
</html>