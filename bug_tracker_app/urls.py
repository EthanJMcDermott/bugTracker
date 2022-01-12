from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.index),
    path('login', views.login),
    path('register', views.register),
    path('login/success', views.user_login),
    path('login/register', views.user_registration),
    path('projects', views.projects),
    path('tickets', views.tickets),
    path('projects/add', views.add_project),
    path('projects/<int:projectid>', views.view_project),
    path('projects/<int:projectid>/add_user', views.add_project_user),
    path('tickets/add', views.add_ticket),
    path('comments/add', views.comment),
    path('comments/<int:commentid>/delete', views.delete_comment),
    path('tickets/<int:ticketid>', views.ticket_view),
    path('tickets/comments/add', views.add_ticket_comment),
    path('tickets/comments/<int:commentid>/delete', views.delete_ticket_comment),
    path('tickets/<int:ticketid>/delete', views.delete_ticket),
    path('tickets/<int:ticketid>/submit', views.submit_ticket),
    path('tickets/<int:ticketid>/resolve', views.resolve_ticket),
    path('tickets/<int:ticketid>/edit', views.edit_ticket),
    path('tickets/<int:ticketid>/edit/success', views.edit_ticket_submit),
    path('user/<int:userid>', views.user),
    path('user/<int:userid>/edit', views.edit_user),
    path('admin', views.admin),
    path('admin/<int:userid>/edit', views.admin_edit_user),
    path('admin/users/<int:userid>/delete', views.admin_delete_user),
    path('logout', views.logout),
    path('about', views.about)
]