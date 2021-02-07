import logging
from datetime import datetime

import mongoengine
from flask import Flask, flash, render_template, request, Response, url_for, g, session, abort, send_from_directory
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_principal import Permission, RoleNeed, AnonymousIdentity, identity_changed, Identity, Principal, \
    identity_loaded, UserNeed, current_app
from flask_security import MongoEngineUserDatastore, Security
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash
from werkzeug.urls import url_parse
from werkzeug.utils import redirect

from helpers.flask_pager import Pager
from helpers.helper import get_current_user_roles
from model import db, Role, User, Voter, Circuit, Box, Party, Votes, Counter, OtherVotes
from config import COLORS, SECRET, PARTIES, VOTES_MATRIX, CANDIDATES, USERS, DOMAIN, CIRCUIT, BOXES
from concurrent.futures import ThreadPoolExecutor

import os

executor = ThreadPoolExecutor(2)
app = Flask(__name__)
app.secret_key = SECRET

gunicorn_logger = logging.getLogger('gunicorn.error')
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(logging.DEBUG)

# MongoDB Config
mongo_url = os.environ.get("MONGO_URL", "mongodb://127.0.0.1:27017/padron")
app.config['MONGODB_DB'] = 'padron'
app.config['MONGODB_HOST'] = mongo_url
app.config['MONGODB_PORT'] = 27017
db.init_app(app)
user_datastore = MongoEngineUserDatastore(db, User, Role)

Bootstrap(app)

principals = Principal(app)
principals.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)
app.config['SECURITY_MSG_UNAUTHORIZED'] = ('Permisos insuficientes para ver recurso.', 'error')
security = Security(app)
# security.init_app(app)

serializer = URLSafeTimedSerializer(SECRET)

# Create a permission with a single Need, in this case a RoleNeed.
admin_permission = Permission(RoleNeed('admin'))
fiscal_permission = Permission(RoleNeed('fiscal'))
escuela_permission = Permission(RoleNeed('escuela'))
general_permission = Permission(RoleNeed('general'))
candidato_permission = Permission(RoleNeed('candidato'))


def votes_constructor():
    votes = Votes(
        president=Counter(),
        gobernor=Counter(),
        diputado=Counter(),
        senador=Counter(),
        intendente=Counter(),
        general=Counter()
    )
    votes.save()
    return votes


def load_votes_matrix(box):
    parties = []
    parties_matrix = zip(PARTIES, VOTES_MATRIX)
    for party, flags in dict(parties_matrix).items():
        kwargs = {}
        for i, flag in enumerate(flags):
            counter = Counter(enabled=bool(flag))
            kwargs[CANDIDATES[i]] = counter
        _votes = Votes(**kwargs)
        _votes.save()
        _party = Party(name=party, votes=_votes)
        _party.save()
        parties.append(_party)
    box.parties = parties
    box.save()
    other_votes = OtherVotes(
        blank=votes_constructor(),
        nulled=votes_constructor(),
        recurrent=votes_constructor(),
        refuted=votes_constructor()
    ).save()
    box.other_votes = other_votes
    box.save()


def load_users():
    if USERS:
        for circuit in USERS:
            for user, details in circuit["usuarios"].items():
                roles = []
                for box in details["boxes"]:
                    roles.append(user_datastore.find_or_create_role(str(box)))

                for role in details["roles"]:
                    roles.append(user_datastore.find_or_create_role(str(role)))
                if not user_datastore.find_user(username=user):
                    user_datastore.create_user(
                        username=user,
                        email=f'{user}@{DOMAIN}',
                        password=generate_password_hash(details["clave"]),
                        roles=roles
                    )
                else:
                    user = user_datastore.find_user(username=user)
                    user.update(
                        password=generate_password_hash(details["clave"]),
                        roles=roles,
                        first_login=True,
                    )


def init_app():
    try:
        app.logger.debug("Adding users")
        load_users()

        app.logger.debug("Adding voters")
        for box in BOXES:
            app.logger.debug(f"Processing box: {box}")

            box_obj = Box.objects(number=box).first()
            if not box_obj:
                box_obj = Box(number=box)
                load_votes_matrix(box_obj)
            for i in range(1, 350 + 1):
                voter_obj = Voter.objects(
                    order=i,
                    box=box_obj
                ).first()
                if not voter_obj:
                    circuit_obj = Circuit.objects(name=CIRCUIT).first()
                    if not circuit_obj:
                        circuit_obj = Circuit(name=CIRCUIT).save()
                    try:
                        Voter(
                            order=i,
                            box=box_obj,
                            circuit=circuit_obj,
                        ).save()
                    except mongoengine.errors.NotUniqueError:
                        continue
    except Exception:
        app.logger.exception("There was something wrong with init.")

    app.logger.debug("Done init")


executor.submit(init_app)


@login_manager.user_loader
def load_user(user_id):
    app.logger.debug("Loading user: %s" % user_id)
    user = User.objects(pk=user_id).first()
    app.logger.debug(user)
    return user


@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    # Set the identity user object
    identity.user = current_user
    app.logger.debug("Loading identity")

    # Add the UserNeed to the identity
    if hasattr(current_user, 'id'):
        app.logger.debug("current_user has id: %s" % current_user.id)
        identity.provides.add(UserNeed(current_user.id))

    # Assuming the User model has a list of roles, update the
    # identity with the roles that the user provides
    if hasattr(current_user, 'roles'):
        app.logger.debug("current_user has roles")
        for role in current_user.roles:
            identity.provides.add(RoleNeed(role.name))


@app.before_request
def before_request():
    g.user = current_user
    app.logger.debug('current_user: %s, g.user: %s, entering bef_req' % (current_user, g.user))


@app.errorhandler(403)
def page_not_found(e):
    app.logger.debug(e)
    flash('El recurso solicitado requiere autenticacion.')
    session['redirected_from'] = request.url
    return redirect(url_for('logout'))


@app.errorhandler(500)
def handle_internal_server_error(e):
    app.logger.debug(e)
    flash('Algo ha ido mal. Pruebe de nuevo.')
    session['redirected_from'] = request.url
    return redirect(url_for('home'))


@app.route('/health', methods=['GET'])
def return_ok():
    return 'Ok!', 200


@app.route('/login', methods=['POST', 'GET'])
def login():
    app.logger.debug(current_user)
    if current_user.is_authenticated:
        app.logger.info("User is authenticated")
        return redirect(url_for("padron"))

    if request.method == 'POST':
        app.logger.debug("Looking up user")
        user = User.objects(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            app.logger.debug("Password is correct")
            app.logger.debug("user: %s" % user.username)

            login_user(user, remember=True)
            app.logger.debug("first login: %s" % user.first_login)

            identity_changed.send(
                current_app._get_current_object(),
                identity=Identity(user)
            )

            app.logger.debug("user is authenticated: %s" % current_user.is_authenticated)

            next_page = request.args.get('next')
            app.logger.debug("Redirecting from login")
            if not next_page or url_parse(next_page).netloc != '':
                return redirect(url_for("padron"))
            return redirect(next_page)
        else:
            flash('Usuario o contraseña incorrectos')
    app.logger.info("User is NOT authenticated")
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()

    # Remove session keys set by Flask-Principal
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)

    # Tell Flask-Principal the user is anonymous
    identity_changed.send(
        current_app._get_current_object(),
        identity=AnonymousIdentity()
    )

    return redirect(url_for('login'))


@app.route('/')
@login_required
def home():
    app.logger.debug("Entered home")
    app.logger.debug(current_user)
    if not current_user.is_authenticated:
        app.logger.debug("Current_user is not authenticated")
        return redirect(url_for("login"))
    app.logger.debug("User is authenticated")
    return redirect(url_for("padron"))


@app.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')


@app.route('/padron')
@login_required
def padron():
    app.logger.info("Entered Padron")

    _roles = get_current_user_roles(current_user)
    app.logger.debug(_roles)
    try:
        _roles = _roles[0]
    except IndexError:
        _roles = None

    if _roles:
        return redirect(url_for('padron_box', box_number=_roles))
    else:
        if not current_user.has_role("admin"):
            flash("Este usuario parece no tener permisos.")
            return redirect(url_for('login'))
        else:
            return redirect(url_for("summary"))


@app.route('/padron/<box_number>')
@login_required
def padron_box(box_number):
    box_permission = Permission(RoleNeed(str(box_number)))
    app.logger.info("Entered Padron for box: %s" % box_number)
    _roles = get_current_user_roles(current_user)
    app.logger.debug("Roles: %s" % _roles)
    app.logger.debug("box_permission: %s" % box_permission)

    pager = Pager(int(box_number), [int(role) for role in _roles])
    pages = pager.get_pages()
    box = Box.objects(number=box_number).first()
    _padron = Voter.objects(box=box)
    if box_permission.can():
        return render_template(
            'padron.html',
            padron=_padron,
            pages=pages,
            box_number=box_number,
        )
    else:
        abort(403)


@app.route('/export')
@login_required
def export():
    boxes = Box.objects()
    padron = []
    for box in boxes:
        voters = Voter.objects(box=box)
        for voter in voters:
            padron.append([
                voter.order,
                voter.status,
                box.number,
            ])
    return render_template(
        'export.html',
        padron=padron,
    )


@app.route('/boxes')
@login_required
@admin_permission.require(http_exception=403)
def boxes():
    app.logger.info("Entered Mesas")
    boxes = Box.objects()
    return render_template('boxes.html', boxes=boxes)


@app.route('/summary')
@login_required
@admin_permission.require(http_exception=403)
def summary():
    _filter = get_current_user_roles(current_user)

    boxes = Box.objects(number__in=_filter).order_by("-number")
    custom_boxes = []
    for box in boxes:
        custom_box = {
            'number': box.number,
            "recurrido": Voter.objects(box=box, status=2).count(),
            "voto": Voter.objects(box=box, status=3).count(),
            "ausentes": Voter.objects(box=box, status=4).count()
        }

        custom_boxes.append(custom_box)
    votos_recurrido = Voter.objects(status=2, box__in=boxes).count()
    votos_ns_nc = Voter.objects(status=3, box__in=boxes).count()
    votos_ausentes = Voter.objects(status=4, box__in=boxes).count()
    data = [
        {"intention": "Recurrido", "count": votos_recurrido},
        {"intention": "Voto", "count": votos_ns_nc},
        {"intention": "Ausentes", "count": votos_ausentes},
    ]
    values = [votos_recurrido, votos_ns_nc, votos_ausentes]
    labels = ["Recurrido", "Voto", "Ausentes"]

    return render_template(
        'summary.html',
        values=values,
        labels=labels,
        colors=COLORS,
        boxes=custom_boxes,
        data=data,
    )


@app.route('/telegram')
@login_required
def telegram():
    app.logger.debug("Entered telegram")
    _filter = get_current_user_roles(current_user)

    box = Box.objects(number__in=_filter).first()
    if box:
        return redirect(url_for('telegram_box', box_number=box.number))
    else:
        return redirect(url_for('padron'))


@app.route('/telegram/<box_number>')
@login_required
def telegram_box(box_number):
    box_permission = Permission(RoleNeed(box_number))
    app.logger.debug("Entered telegram %s" % box_number)
    _roles = get_current_user_roles(current_user)

    boxes = Box.objects(number__in=_roles).order_by("number")
    pager = Pager(int(box_number), [int(box.number) for box in boxes])
    pages = pager.get_pages()
    if box_permission.can():
        box = Box.objects(number=box_number).first()
        if box:
            return render_template(
                'telegram.html',
                parties=box.parties,
                other_votes=box.other_votes,
                pages=pages,
                box_number=box.number)
        else:
            flash("Mesa inexistente")
            return redirect(url_for('padron'))
    else:
        abort(403)


@app.route('/totales')
@login_required
def totales():
    candidates = ["president", "gobernor", "diputado", "senador", "intendente", "general"]
    other_votes = ["blank", "nulled", "recurrent", "refuted"]
    app.logger.debug("Entered totales")
    _filter = get_current_user_roles(current_user)

    boxes = Box.objects(number__in=_filter)
    results = {}
    other_results = {}
    for box in boxes:
        for party in box.parties:
            if not results.get(party.name):
                results[party.name] = {}
            for candidate in candidates:
                if not results[party.name].get(candidate):
                    results[party.name][candidate] = {}
                results[party.name][candidate]["count"] = \
                    results[party.name][candidate].get("count", 0) + party.votes[candidate].count
                results[party.name][candidate]["enabled"] = party.votes[candidate].enabled
        for vote_type in other_votes:
            if not other_results.get(vote_type):
                other_results[vote_type] = {}
            for candidate in candidates:
                if not other_results[vote_type].get(candidate):
                    other_results[vote_type][candidate] = {}
                other_results[vote_type][candidate]["count"] = \
                    other_results[vote_type][candidate].get("count", 0) + box.other_votes[vote_type][candidate].count
                other_results[vote_type][candidate]["enabled"] = box.other_votes[vote_type][candidate].enabled

    if results:
        return render_template('totales.html', results=results, other_results=other_results)
    else:
        return redirect(url_for('padron'))


@app.route('/ayuda')
@login_required
def ayuda():
    app.logger.debug("Entered help")
    return render_template('help.html')


@app.route('/contacts')
@login_required
def contacts():
    app.logger.debug("Entered contacts")
    return render_template('contacts.html')


@app.route('/save_state/<order>', methods=["POST"])
@login_required
def save_state(order):
    app.logger.debug("Saving order: %s" % order)
    box = Box.objects(number=request.form.get("box")).first()
    voter = Voter.objects(order=order, box=box).first()
    voter.update(status=request.form.get("intencion"), last_updated=datetime.now())
    return Response(status=200)


@app.route('/save_results', methods=["POST"])
@login_required
def save_results():
    other_votes = ["blank", "nulled", "recurrent", "refuted"]
    app.logger.debug("Saving results")
    field_id = request.form.get("field_id")
    _value = request.form.get("value")
    _id = field_id.split(".")[0]

    if _id in other_votes:
        other_votes = OtherVotes.objects(id=field_id.split(".")[1]).first()
        votes = other_votes[_id]
        votes[field_id.split(".")[2]].count = _value
        votes.save()
    else:
        party_obj = Party.objects(id=_id).first()
        votes = party_obj.votes
        votes[field_id.split(".")[1]].count = _value
        votes.save()

    return Response(status=200)


if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0', port=4000)
