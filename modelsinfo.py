from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Car, Base, Model, User

engine = create_engine('sqlite:///carswithusers2.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

User1 = User(name="David B.", email="tinnyTim@udacity.com",
             picture='https://www.famousbirthdays.com/headshots/david-beckham-1.jpg')
session.add(User1)
session.commit()


car1 = Car(user_id=1, name="Tesla", sign="http://www.carlogos.org/logo/Tesla-emblem-2003-1366x768.png")

session.add(car1)
session.commit()

model1 = Model(user_id=1, name="Model S", price="From $ 73,000", car_class="Electric",
                     electric_range="479.6 to 613.2 km battery-only", car=car1)

session.add(model1)
session.commit()

model2 = Model(user_id=1, name="Model 3", price="From $ 35,000", car_class="Electric",
                     electric_range="350 to 797 km battery-only", car=car1)

session.add(model2)
session.commit()


car2 = Car(user_id=1, name="BMW", sign="http://agarioskins.com/submitted/useruploads/upraveny_283657-bmw-logo.png")

session.add(car2)
session.commit()

model3 = Model(user_id=1, name="BMW i3", price="From $ 42,000", car_class="Electric",
                     electric_range="241.4 km battery-only, 300 km total", car=car2)

session.add(model3)
session.commit()

model4 = Model(user_id=1, name="BMW i8", price="From $ 135,000", car_class="Hybrid",
                     electric_range="37 km battery-only", car=car2)

session.add(model4)
session.commit()




print "added cars!"