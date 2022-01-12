from django.shortcuts import render, redirect
from .models import *
import bcrypt
from django.contrib import messages, auth
from .decorators import unauthenticated_user
from django.db.models import Count, Q
import datetime
from django.contrib.auth.decorators import login_required
from .decorators import unauthenticated_user
import functools

# Create your views here.
def index(request):
    try:
        request.session['user_id']
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
        this_company = this_user.company
        user_tickets = Ticket.objects.filter(user=this_user)
        low_tickets = user_tickets.filter(priority = 1).count()
        medium_tickets = user_tickets.filter(priority = 2).count()
        high_tickets = user_tickets.filter(priority = 3).count()
        projects = Project.objects.filter(users=this_user)
        projects = Project.objects.annotate(num_tickets=Count('tickets', distinct=True)).filter(tickets__user=this_user)
        tickets_by_project = Ticket.objects.order_by('title')
        tickets_by_project = tickets_by_project.values('project__title').annotate(num_tickets=Count('id')).filter(user=this_user).order_by()
        total_tickets_open = Ticket.objects.filter(status__in=[1,2]).filter(company=this_company).count()
        total_tickets_closed = Ticket.objects.filter(status=4).filter(company=this_company).count()
        user_tickets_total = user_tickets.filter(status__in=[1,2]).count()
        user_tickets_closed = user_tickets.filter(status=4).count()
        context = {
            "today": today,
            "weekday": week_day,
            "tickets": Ticket.objects.filter(user=this_user),
            "low": low_tickets,
            "medium": medium_tickets,
            "high": high_tickets,
            "projects": projects,
            "project_tickets": tickets_by_project,
            "months": month_list,
            "total_tickets_open": total_tickets_open,
            "total_tickets_closed": total_tickets_closed,
            "user_tickets_total": user_tickets_total,
            "user_tickets_closed": user_tickets_closed

        }
        return render(request, 'index.html', context)
    except:
        return redirect('/login')


### USER LOGIN AND REGISTRATION ###
def login(request):
    return render(request, 'login.html')

def register(request):
    return render(request, 'register.html')

def user_registration(request):
    if request.method == "POST":
        errors = User.objects.register_validator(request.POST)
        if request.POST['company_code'] != "" or request.POST['new_company_code']:
            company_errors = Company.objects.company_validator(request.POST)
            for key, value in company_errors.items():
                messages.error(request, value)
        if len(errors) > 0 or len(company_errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/register')
        password = request.POST["password"]
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user = User.objects.filter(email=request.POST['email'])
        if request.POST['company_code'] != "":
            company_code = request.POST["company_code"]
            company_code_hash = bcrypt.hashpw(company_code.encode(), bcrypt.gensalt()).decode()
            User.objects.create(first_name=request.POST["first_name"], last_name=request.POST["last_name"], email=request.POST["email"], password=pw_hash, company=Company.objects.get(company_name=request.POST['old_company_name']))
        else:
            new_company_code = request.POST["new_company_code"]
            new_company_code_hash = bcrypt.hashpw(new_company_code.encode(), bcrypt.gensalt()).decode()
            Company.objects.create(company_name=request.POST['company_name'], company_code=new_company_code_hash)
            User.objects.create(first_name=request.POST["first_name"], last_name=request.POST["last_name"], email=request.POST["email"], password=pw_hash, user_role=3, company=Company.objects.get(company_code=new_company_code_hash))
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

### PROJECTS PAGE RENDER AND FUNCTIONS ###

##########################################
def projects(request):
    try:
        request.session['user_id']
        this_user = User.objects.get(id=request.session['user_id'])
        this_company = this_user.company
        admin = [2,3]
        context = {
            "this_user": this_user,
            "users": User.objects.filter(company=this_company),
            "projects": Project.objects.filter(company=this_company),
            "admin": admin
        }
        return render(request, 'projects.html', context)
    except:
        return redirect('/login')

def add_project(request):
    if request.method == "POST":
        current_user = User.objects.get(id=request.session['user_id'])
        this_company = current_user.company
        new_project_manager = User.objects.get(id=request.POST['project_manager'])
        new_project = Project.objects.create(title=request.POST['title'], description=request.POST['description'], project_manager=new_project_manager, created_by=current_user, company=this_company)
        new_project.users.add(current_user)
    return redirect('/projects')


###############################################

### INDIVIDUAL PROJECT RENDER AND FUNCTIONS ###

###############################################
def view_project(request, projectid):
    try:
        request.session['user_id']
        project = Project.objects.get(id=projectid)
        this_company = project.company
        admin = [2,3]
        context = {
            "project": project,
            "users": project.users.all(),
            "tickets": project.tickets.all(),
            "comments": project.comments.all().reverse(),
            "all_users": User.objects.filter(company=this_company),
            "admin": admin
        }
        return render(request, 'project_view.html', context)
    except:
        return redirect('/login')

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
        this_user = User.objects.get(id=request.session['user_id'])
        this_company = this_user.company
        try:
            this_user = User.objects.get(id=request.POST['user'])
            ticket_status = 2
            Ticket.objects.create(title=request.POST["title"], description=request.POST["description"], priority=request.POST["priority"], status=ticket_status, project=this_project, user=this_user, company=this_company)
        except:
            ticket_status = 1
            Ticket.objects.create(title=request.POST["title"], description=request.POST["description"], priority=request.POST["priority"], status=ticket_status, project=this_project, company=this_company)
        projectid = request.POST['project'] 
        return redirect(f'/projects/{projectid}')
    return redirect('/projects')


###############################################

### INDIVIDUAL TICKET RENDER AND FUNCTIONS ###

###############################################
def tickets(request):
    try:
        request.session['user_id']
        context = {
            "tickets": Ticket.objects.all()
        }
        return render(request, 'tickets.html', context)
    except:
        return redirect('/login')

def ticket_view(request, ticketid):
    try:
        request.session['user_id']
        ticket = Ticket.objects.get(id=ticketid)
        context = {
            "ticket": ticket,
            "comments": ticket.comments.all().reverse(),
        }
        return render(request, 'ticket_view.html', context)
    except:
        return redirect('/login')

def add_ticket_comment(request):
    if request.method == "POST":
        this_ticket = Ticket.objects.get(id=request.POST['ticket'])
        this_user = User.objects.get(id = request.session['user_id'])
        ticket_id = request.POST['ticket']
        TicketComment.objects.create(comment=request.POST['comment'], user=this_user, ticket=this_ticket)
    return redirect(f'/tickets/{ticket_id}')

def delete_ticket_comment(request, commentid):
    if request.method == "POST":
        this_comment = TicketComment.objects.get(id=commentid)
        this_ticket = this_comment.ticket.id
        this_comment.delete()
    return redirect(f'/tickets/{this_ticket}')

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
    if request.method == "POST":
        this_ticket = Ticket.objects.get(id=ticketid)
        this_ticket.delete()
    return redirect('/projects')

def edit_ticket(request, ticketid):
    try:
        request.session['user_id']
        context = {
            "ticket": Ticket.objects.get(id=ticketid),
            "users": User.objects.all()
        }
        return render(request, 'edit_ticket.html', context)
    except:
        return redirect('/login')

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
    try:
        request.session['user_id']
        if request.session['role'] not in [2,3]:
            return redirect('/')
        else:
            this_user = User.objects.get(id=request.session['user_id'])
            this_company = this_user.company
            context = {
                "tickets": Ticket.objects.filter(company=this_company),
                "users": User.objects.filter(company=this_company)
            }
            return render(request, 'admin.html', context)
    except:
        return redirect('/login')

def user(request, userid):
    try:
        request.session['user_id']
        this_user = User.objects.get(id=request.session['user_id'])
        this_company = this_user.company
        context = {
            "this_company": this_company
        }
        return render(request, 'user.html', context)
    except:
        return redirect('/login')

def edit_user(request, userid):
    if request.method == "POST":
        this_user = User.objects.get(id=request.session['user_id'])
        this_user.first_name = request.POST['first_name']
        this_user.last_name = request.POST['last_name']
        this_user.email = request.POST['email']
        this_user.save()
    return redirect('/')

def admin_edit_user(request, userid):
    if request.method == "POST":
        this_user = User.objects.get(id=userid)
        this_user.first_name = request.POST['first_name']
        this_user.last_name = request.POST['last_name']
        this_user.email = request.POST['email']
        this_user.save()
    return redirect('/admin')

def admin_delete_user(request, userid):
    if request.method == "POST":
        this_user = User.objects.get(id=userid)
        this_user.delete()
    return redirect('/admin')

def logout(request):
    auth.logout(request)
    return redirect('/login')

def about(request):
    return render(request, 'about.html')