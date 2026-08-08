from main import (
    db_session, User, Complaint, ComplaintClassification,
    ComplaintAssignment, Feedback
)

# Delete in dependency order (children before parents) to avoid
# foreign key errors, since none of your relationships have
# cascade="all, delete" configured.
db_session.query(Feedback).delete()
db_session.query(ComplaintAssignment).delete()
db_session.query(ComplaintClassification).delete()
db_session.query(Complaint).delete()
db_session.query(User).delete()

db_session.commit()

print("All users and dependent records cleared.")