from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Place, Base, Taco, Rate, MeatType, User

#engine = create_engine('sqlite:///best_tacos.db')
engine = create_engine('postgres://besttacos:XXXXX@localhost:5432/besttacos')
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


# Create dummy user
User1 = User(name="Robo Barista", email="tinnyTim@udacity.com",
             picture='https://pbs.twimg.com/profile_images/\
             2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

user2 = User(email='foobar@example.com',
             name='Sample user')
user2.hash_password('foobar')
session.add(user2)
session.commit()

for i in range(6):
    rating1 = Rate(rate=i)
    session.add(rating1)
    session.commit()

# Place
pic = 'http://4.bp.blogspot.com/-Os9gOHAXiJQ/Uf9KLEQicyI/'
pic += 'AAAAAAAAL3A/VHL2jhL7w2c/IMG_3469.JPG'
place1 = Place(user_id=1, name="Metro Balderas 1",
               picture=pic,
               rate_id=2)

session.add(place1)
session.commit()

# MeatType
meatType1 = MeatType(user_id=1, name="Pork", description="None veggie")
session.add(meatType1)
session.commit()
meatType2 = MeatType(user_id=1, name="Beef", description="None veggie")
session.add(meatType2)
session.commit()
meatType3 = MeatType(user_id=1, name="Chicken", description="None veggie")
session.add(meatType3)
session.commit()
meatType4 = MeatType(user_id=1, name="Veggie", description="Veggie")
session.add(meatType4)
session.commit()

pic = 'http://zonaguadalajara.com/wp-content/uploads/2015/10/'
pic += 'Tacos-al-Pastor-Jalisco.jpg'
taco1 = Taco(user_id=1,
             name="Pastor",
             description="Marinated pork with corn tortilla",
             price="6.50",
             picture=pic,
             place=place1,
             meat_type=meatType1)

session.add(taco1)
session.commit()
print("Tacos added P")
