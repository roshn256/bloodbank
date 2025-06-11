from flask_sqlalchemy import SQLAlchemy 
from datetime import datetime, date, time

# Initialize SQLAlchemy

from sqlalchemy.dialects.postgresql import TIMESTAMP 

db = SQLAlchemy()

# Association table for many-to-many between Events and Donors
event_donors = db.Table(
    'event_donors',
    db.Column('event_id', db.Integer, db.ForeignKey('event.id'), primary_key=True),
    db.Column('donor_id', db.Integer, db.ForeignKey('donor.id'), primary_key=True)
)

class Event(db.Model):
    __tablename__ = 'event'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    location_name = db.Column(db.String(200), nullable=False)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    description = db.Column(db.Text, nullable=True)

    # Statistics fields
    registered = db.Column(db.Integer, default=0)
    donated = db.Column(db.Integer, default=0)
    units = db.Column(db.Integer, default=0)
    progress = db.Column(db.Integer, default=0)

    # Status tracking
    is_active = db.Column(db.Boolean, default=True)

    # Timestamps
    created_at = db.Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    updated_at = db.Column(TIMESTAMP(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship to donors (who registered)
    donors = db.relationship('Donor', secondary=event_donors, back_populates='events')

    def __repr__(self):
        return f"<Event {self.title} on {self.date}>"

class Donor(db.Model):
    __tablename__ = 'donor'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    blood_group = db.Column(db.String(3), nullable=False)

    # Location data
    last_donation_date = db.Column(db.Date, nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='active')

    # Timestamps
    created_at = db.Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    updated_at = db.Column(TIMESTAMP(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship to events they registered for
    events = db.relationship('Event', secondary=event_donors, back_populates='donors')

    def __repr__(self):
        return f"<Donor {self.name} ({self.blood_group})>"