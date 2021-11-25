from django.shortcuts import render, redirect
from .models import *
import bcrypt
from django.contrib import messages, auth
from .decorators import unauthenticated_user
from django.db.models import Count, Q
import datetime
from django.contrib.auth.decorators import login_required
from .decorators import *


# Create your views here.
def index(request):
    today = datetime.date.today() 
    week_day = datetime.date.today().strftime('%A')
    month = datetime.datetime.today().month
    month_list = []
    month = 1
    while len(month_list) < 3:
        month_list.append(month)
        month -= 1
        if month < 1:
            month = 12
    this_user = User.objects.get(id=request.session['user_id'])
    user_tickets = Ticket.objects.filter(user=this_user)
    low_tickets = user_tickets.filter(priority = 1).count()
    medium_tickets = user_tickets.filter(priority = 2).count()
    high_tickets = user_tickets.filter(priority = 3).count()
    projects = Project.objects.filter(users=this_user)
    projects = Project.objects.annotate(num_tickets=Count('tickets', distinct=True)).filter(tickets__user=this_user)
    tickets_by_project = Ticket.objects.order_by('title')
    tickets_by_project = tickets_by_project.values('project__title').annotate(num_tickets=Count('id')).filter(user=this_user).order_by()
    context = {
        "today": today,
        "weekday": week_day,
        "tickets": Ticket.objects.filter(user=this_user),
        "low": low_tickets,
        "medium": medium_tickets,
        "high": high_tickets,
        "projects": projects,
        "project_tickets": tickets_by_project,
        "months": month_list
    }
    return render(request, 'index.html', context)


### USER LOGIN AND REGISTRATION ###
def login(request):
    return render(request, 'login.html')

def register(request):
    return render(request, 'register.html')

def user_registration(request):
    if request.method == "POST":
        errors = User.objects.register_validator(request.POST)
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/login')
        password = request.POST["password"]
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        User.objects.create(first_name=request.POST["first_name"], last_name=request.POST["last_name"], email=request.POST["email"], password=pw_hash)
        user = User.objects.filter(email=request.POST['email'])
        if user:
            logged_user = user[0]
            request.session['user_id'] = logged_user.id
            request.session['user_first_name'] = logged_user.first_name
            request.session['user_last_name'] = logged_user.last_name
            request.session['user_email'] = logged_user.email
            request.session['role'] = logged_user.user_role
            request.session['is_authenticated'] = True
    return redirect('/')

def user_login(request):
    if request.method == "POST":
        errors = User.objects.login_validator(request.POST)
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/login')
        user = User.objects.filter(email=request.POST['email'])
        if user:
            logged_user = user[0]
            if bcrypt.checkpw(request.POST['password'].encode(), logged_user.password.encode()):
                request.session['user_id'] = logged_user.id
                request.session['user_first_name'] = logged_user.first_name
                request.session['user_last_name'] = logged_user.last_name
                request.session['user_email'] = logged_user.email
                request.session['role'] = logged_user.user_role
                request.session['is_authenticated'] = True
                return redirect('/')

def logout(request):
    auth.logout(request)
    return redirect('/login')


##########################################

### PROJECTS PAGE RENDER AND FUNCTIONS ###d 2`1

##########################################
def projects(request):
    this_user = User.objects.get(id=request.session['user_id'])
    admin = [2,3]
    context = {
        "this_user": this_user,
        "users": User.objects.all(),
        "projects": Project.objects.all(),
        "admin": admin
    }
    return render(request, 'projects.html', context)

def add_project(request):
    if request.method == "POST":
        current_user = User.objects.get(id=request.session['user_id'])
        new_project_manager = User.objects.get(id=request.POST['project_manager'])
        new_project = Project.objects.create(title=request.POST['title'], description=request.POST['description'], project_manager=new_project_manager, created_by=current_user)
        new_project.users.add(current_user)
    return redirect('/projects')


###############################################

### INDIVIDUAL PROJECT RENDER AND FUNCTIONS ###

###############################################
def view_project(request, projectid):
    project = Project.objects.get(id=projectid)
    admin = [2,3]
    context = {
        "project": project,
        "users": project.users.all(),
        "tickets": project.tickets.all(),
        "comments": project.comments.all().reverse(),
        "all_users": User.objects.all(),
        "admin": admin
    }
    return render(request, 'project_view.html', context)

def add_project_user(request, projectid):
    if request.method == "POST":
        this_user = User.objects.get(id=request.POST['add-project-user'])
        this_project = Project.objects.get(id=projectid)
        this_project.users.add(this_user)
    return redirect(f'/projects/{projectid}')

def comment(request):
    if request.method == "POST":
        this_project = Project.objects.get(id=request.POST['project'])
        this_user = User.objects.get(id=request.session['user_id'])
        projectid = request.POST['project'] 
        Comment.objects.create(comment=request.POST['comment'], user=this_user, project=this_project)
    return redirect(f'/projects/{projectid}')

def delete_comment(request, commentid):
    if request.method == "POST":
        this_comment = Comment.objects.get(id=commentid)
        this_project = this_comment.project.id
        this_comment.delete()
    return redirect(f'/projects/{this_project}')

def add_ticket(request):
    if request.method == "POST":
        this_project = Project.objects.get(id=request.POST['project'])
        try:
            this_user = User.objects.get(id=request.POST['user'])
            ticket_status = 2
            Ticket.objects.create(title=request.POST["title"], description=request.POST["description"], priority=request.POST["priority"], status=ticket_status, project=this_project, user=this_user)
        except:
            ticket_status = 1
            Ticket.objects.create(title=request.POST["title"], description=request.POST["description"], priority=request.POST["priority"], status=ticket_status, project=this_project)
        projectid = request.POST['project'] 
        return redirect(f'/projects/{projectid}')
    return redirect('/projects')


###############################################

### INDIVIDUAL TICKET RENDER AND FUNCTIONS ###

###############################################
def tickets(request):
    context = {
        "tickets": Ticket.objects.all()
    }
    return render(request, 'tickets.html', context)

def ticket_view(request, ticketid):
    context = {
        "ticket": Ticket.objects.get(id=ticketid)
    }
    return render(request, 'ticket_view.html', context)

def submit_ticket(request, ticketid):
    if request.method == "POST":
        this_ticket = Ticket.objects.get(id=ticketid)
        this_ticket.status = request.POST['ticket-status']
        this_ticket.save()
    return redirect(f'/tickets/{ticketid}')

def resolve_ticket(request, ticketid):
    if request.method == "POST":
        this_ticket = Ticket.objects.get(id=ticketid)
        this_ticket.status = request.POST['ticket-status']
        this_ticket.save()
    return redirect(f'/tickets/{ticketid}')

def delete_ticket(request, ticketid):
    this_ticket = Ticket.objects.get(id=ticketid)
    this_ticket.delete()
    return redirect('/projects')

def edit_ticket(request, ticketid):
    context = {
        "ticket": Ticket.objects.get(id=ticketid),
        "users": User.objects.all()
    }
    return render(request, 'edit_ticket.html', context)

def edit_ticket_submit(request, ticketid):
    if request.method == "POST":
        ticket_edit = Ticket.objects.get(id=ticketid)
        ticket_edit.title = request.POST["title"]
        ticket_edit.priority = request.POST["priority"]
        ticket_edit.description = request.POST["description"]
        ticket_edit.user = User.objects.get(id=request.POST["user"])
        ticket_edit.save()
    return redirect(f'/tickets/{ticketid}')

def admin(request):
    if request.session['role'] not in [2,3]:
        return redirect('/')
    else:
        context = {
            "tickets": Ticket.objects.all(),
            "users": User.objects.all()
        }
        return render(request, 'admin.html', context)

def user(request, userid):
    return render(request, 'user.html')

def edit_user(request, userid):
    if request.method == "POST":
        this_user = User.objects.get(id=request.session['user_id'])
        this_user.first_name = request.POST['first_name']
        this_user.last_name = request.POST['last_name']
        this_user.email = request.POST['email']
        this_user.save()
    return redirect('/')

def logout(request):
    auth.logout(request)
    return redirect('/login')
