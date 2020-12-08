<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@page session="true"%>
<html>
<head>
    <title>Show Projects</title>
    <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
</head>
<body>
<jsp:include page="menu.jsp" />
<center>
<h1 style="color: red;">${projectName}</h1>

    <table class="w3-table-all w3-card-4" style="text-align: center">
        <tr>
            <th>Members</th>
            <c:if test="${userRole ne '[ROLE_MEMBER]'}">
            <th>Give Permission</th>
            </c:if>
        </tr>
        <c:forEach var="listValue" items="${users}">
            <tr>
                <td>${listValue.username}</td>
                <td>
                    <c:if test="${showRemoveMember == 0}">
                    <a href="/setMember?id=${listValue.id}&projectId=${projectId}">+</a></td>
                    </c:if>
                    <c:if test="${showRemoveMember == 1 && userRole ne '[ROLE_MEMBER]'}">
                        <a href="/removeMember?id=${listValue.id}&projectId=${projectId}">-</a></td>
                    </c:if>
            </tr>
        </c:forEach>
    </table>
</center>
</body>
</html>