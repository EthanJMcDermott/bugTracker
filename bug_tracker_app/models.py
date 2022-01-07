from django.db import models
import re
import bcrypt

# Create your models here.
class UserManager(models.Manager):
    def register_validator(self, postData):
        errors = {}
        EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$")
        # PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$")
        if len(postData['first_name']) < 2 or len(postData['last_name']) < 2:
            errors["name"] = "First and Last name should contain at least 2 characters"
        if len(User.objects.filter(email=postData['email'])) > 0:
            errors["emailAlreadyExists"] = "A user with this email already exists"
        if not EMAIL_REGEX.match(postData['email']):
            errors["emailValid"] = "Please enter a valid email"
        if len(postData['password'])<8:
            errors["passwordValid"] = "Passwords must be at least 8 characters long"
        if postData['password'] != postData['password_confirm']:
            errors["passwordMatch"] = "Password and Confirm password must match"
        return errors
    
    def login_validator(self, postData):
        try:
            user = User.objects.filter(email = postData['email'])
            errors = {}
            if user:
                logged_user = user[0]
                if bcrypt.checkpw(postData['password'].encode(), logged_user.password.encode()):
                    return errors
                else:
                    errors['passwordUserMatch'] = "Incorrect email and password combination"
                return errors
            else:
                errors['userNotFound'] = "No user associated with this email address"    
            return errors
        except:
            errors['nouser'] = "no user"
            return errors

class CompanyManager(models.Manager):
    def company_validator(self, postData):
        errors = {}
        if postData['company_code'] != "":
            try:
                company_code = postData["company_code"]
                company_code_hash = bcrypt.hashpw(company_code.encode(), bcrypt.gensalt()).decode()
                company_name = postData["old_company_name"]
                company = Company.objects.filter(company_name = company_name)
                if company:
                    this_company = company[0]
                    print('hello')
                    if bcrypt.checkpw(postData['company_code'].encode(), this_company.company_code.encode()):
                        print('hello world')
                        return errors
                    else:
                        errors['CodeNotFound'] = "Company code not found2"
                else:
                    errors['companyNotFound'] = "Company code not found3"
                return errors
            except:
                error['companyNotFound'] = "Company code not found 1"
        elif postData['company_name'] != "" and postData['new_company_code'] != "":
            if len(Company.objects.filter(company_name=postData['company_name'])) > 0:
                errors['companyAlreadyExists'] = "A company with this name already exists"
            if len(postData['new_company_code']) < 6:
                errros['companyCodeLength'] = 'Company code must be at least 6 characters'
            return errors

class Company(models.Model):
    company_name = models.CharField(max_length=255)
    company_code = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = CompanyManager()

class User(models.Model):
    USER_ROLE_CHOICES = (
        (1, 'developer'),
        (2, 'project_manager'),
        (3, 'admin'),
    )   

    user_role = models.PositiveSmallIntegerField(choices=USER_ROLE_CHOICES, default=1)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    company = models.ForeignKey(Company, related_name="users", on_delete=models.CASCADE)
    objects = UserManager()

class Project(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    project_manager = models.ForeignKey(User, related_name="projects_managed", on_delete=models.CASCADE, null=True)
    created_by = models.ForeignKey(User, related_name="created_projects", on_delete=models.CASCADE)
    users = models.ManyToManyField(User, related_name="current_projects", null=True)
    company = models.ForeignKey(Company, related_name="projects", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Ticket(models.Model):
    PRIORITY_CHOICES = (
        (1, 'low'),
        (2, 'medium'),
        (3, 'high'),
    )

    STATUS_CHOICES = (
        (1, 'unassigned'),
        (2, 'active'),
        (3, 'review'),
        (4, 'resolved'),
    ) 

    title = models.CharField(max_length=255)
    description = models.TextField()
    priority = models.PositiveSmallIntegerField(choices=PRIORITY_CHOICES)
    status = models.PositiveSmallIntegerField(choices=STATUS_CHOICES)
    project = models.ForeignKey(Project, related_name="tickets", on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name="current_tickets", on_delete=models.SET_NULL, null=True)
    company = models.ForeignKey(Company, related_name="tickets", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Report(models.Model):
    ticket = models.ForeignKey(Ticket, related_name="reports", on_delete=models.CASCADE)
    description = models.TextField()
    user = models.ForeignKey(User, related_name="reports", on_delete=models.CASCADE)
    assigned_by = models.ForeignKey(User, related_name="assigned_reports", on_delete=models.CASCADE)
    due_date = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Comment(models.Model):
    comment = models.TextField()
    user = models.ForeignKey(User, related_name="comments", on_delete=models.CASCADE)
    project = models.ForeignKey(Project, related_name="comments", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class TicketComment(models.Model):
    comment = models.TextField()
    user = models.ForeignKey(User, related_name="ticket_comments", on_delete=models.CASCADE)
    ticket = models.ForeignKey(Ticket, related_name="comments", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)





