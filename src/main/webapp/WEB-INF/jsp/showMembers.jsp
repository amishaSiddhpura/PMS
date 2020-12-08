<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@page session="true"%>
<html>
<head>
    <title>Show Members</title>
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
</head>
<body>
<jsp:include page="menu.jsp" />
<center>
    <h1 style="color: red;">Show Members</h1>
    <table class="w3-table-all w3-card-4">
        <tr>
            <th style="text-align: center">USERNAME</th>
        </tr>
        <c:forEach var="listValue" items="${user}">
            <tr>
                <td style="text-align: center"><a href="/memberTask?id=${listValue.id}&username=${listValue.username}">${listValue.username}</a>
                <input type="hidden" value="${listValue.username}" name="username">
                </td>
            </tr>
        </c:forEach>
    </table>

</center>
</body>
</html>