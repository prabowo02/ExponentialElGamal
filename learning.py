from sklearn import svm
from sklearn import linear_model


def load_cleveland():
    data = [[float(num) for num in line.split(',')] for line in open('cleveland.data').readlines() if '?' not in line]
    
    # Age, Sex, Resting blood pressure, Serum cholestoral, Heart rate
    use = [0, 1, 3, 4, 7]
    
    X = [[row[i] for i in use] for row in data]
    Y = [row[-1] for row in data]
    
    return X, Y
    
    
def normalize(X):
    maxi = [max(col) for col in zip(*X)]
    mini = [min(col) for col in zip(*X)]
    
    return [[(row[i] - mini[i]) / (maxi[i] - mini[i]) for i in range(len(X[-1]))] for row in X]
    

def main():
    clf = svm.LinearSVC(max_iter=1000)
    # clf = linear_model.LogisticRegression(solver='liblinear', multi_class='ovr')
    
    X, Y = load_cleveland()
    X = normalize(X)
    
    X_train, Y_train = X[:250], Y[:250]
    X_test, Y_test = X[250:], Y[250:]
    
    clf.fit(X_train, Y_train)
    
    print(clf.coef_)
    print(clf.intercept_)
    
    result = []
    for coef, intercept in zip(clf.coef_, clf.intercept_):
        MULTIPLIER = 1000000
        ls = [int(c * MULTIPLIER) for c in coef]
        ls.append(int(intercept * MULTIPLIER))
        result.append(ls)
    
    print(result)
    
    print(clf.score(X_test, Y_test))
    
    X = [
        [23, 0, 98, 98, 98],
        [90, 0, 44, 44, 44],
    ]
    print(clf.predict(X))
    print(clf.decision_function(X))
    
    
if __name__ == '__main__':
    main()
