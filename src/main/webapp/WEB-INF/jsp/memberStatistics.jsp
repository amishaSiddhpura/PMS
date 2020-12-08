<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@page session="true"%>
<html>
<head>
    <title>Member Statistics</title>
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
</head>
<body>
<jsp:include page="menu.jsp" />
<h3 style="color: red;">Member Statistics</h3>
<center>
    <table class="w3-table-all w3-card-4">
        <tr>
            <th>Assigned Task</th>
            <th>Status</th>
            <th>DESCRIPTION</th>
            <th>CHANGE STATUS</th>
            <%--<th>Deadline</th>--%>
        </tr>
        <c:forEach var="listValue" items="${tasks}">
            <tr>
                <td>${listValue.title}</td>
                <td>${listValue.state}</td>
                <td>${listValue.description}</td>
                <td style="text-align: center"><a href="/changeStatus?id=${listValue.id}">Edit</a> </td>
            </tr>
        </c:forEach>
    </table>

</center>
</body>
</html>